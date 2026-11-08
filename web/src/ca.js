// Выпуск личного root CA и name-constrained proxy рута минцифры.
// Вся низкоуровневая работа с ASN.1/DER делегирована pkijs + asn1js,
// ключи и подписи — нативному WebCrypto.
import * as asn1js from "asn1js";
import {
  AttributeTypeAndValue,
  AuthorityKeyIdentifier,
  BasicConstraints,
  Certificate,
  ECPrivateKey,
  Extension,
  GeneralName,
  GeneralSubtree,
  NameConstraints,
  PublicKeyInfo,
  RelativeDistinguishedNames,
  Time,
} from "pkijs";
import { base64ToBytes, derToPem, pemBlocks, pemToDer, sha1Bytes, sha256Hex } from "./util.js";
import { domainCovered } from "./domains.js";

const OID = {
  CN: "2.5.4.3",
  O: "2.5.4.10",
  basicConstraints: "2.5.29.19",
  keyUsage: "2.5.29.15",
  nameConstraints: "2.5.29.30",
  ski: "2.5.29.14",
  aki: "2.5.29.35",
  ecPublicKey: "1.2.840.10045.2.1",
  prime256v1: "1.2.840.10045.3.1.7",
};

// Subject личного root CA (совпадает с CLI-версией scripts/generate.py).
const ROOT_SUBJECT = [
  [OID.CN, "restricted-russian-ca Personal Root"],
  [OID.O, "restricted-russian-ca"],
];

const EC_PARAMS = { name: "ECDSA", namedCurve: "P-256" };

/** DN из пар [OID, значение] (значения — Utf8String). */
function makeName(pairs) {
  return new RelativeDistinguishedNames({
    typesAndValues: pairs.map(([t, v]) => new AttributeTypeAndValue({
      type: t,
      value: new asn1js.Utf8String({ value: v }),
    })),
  });
}

/** Случайный положительный серийный номер (16 байт, DER-минимальный). */
function serialNumber() {
  const b = new Uint8Array(16);
  crypto.getRandomValues(b);
  b[0] &= 0x7f;                                  // старший бит сброшен → число положительное
  let i = 0;
  while (i < b.length - 1 && b[i] === 0) i++;    // без ведущих нулей
  return new asn1js.Integer({ valueHex: b.slice(i) });
}

/** Срок действия: days=null → бессрочно (до 9999-12-31). */
function validity(days) {
  const now = new Date();
  const until = days ? new Date(now.getTime() + days * 86400000) : new Date("9999-12-31T23:59:59Z");
  // RFC 5280: до 2049 года — UTCTime, далее — GeneralizedTime
  const time = (d) => new Time({ type: d.getUTCFullYear() >= 2050 ? 1 : 0, value: d });
  return { notBefore: time(now), notAfter: time(until) };
}

/**
 * Extension из ASN.1-значения: asn1js-структуры кодируются напрямую (toBER),
 * pkijs-классы — через toSchema().toBER().
 */
function makeExtension(extnID, critical, value) {
  const ber = typeof value.toBER === "function" ? value.toBER(false) : value.toSchema().toBER(false);
  return new Extension({
    extnID, critical,
    extnValue: ber, // сырые байты DER-значения
  });
}

/** keyUsage: keyCertSign + cRLSign (биты 5–6), critical — CA обязан уметь подписывать. */
function keyUsageExt() {
  return makeExtension(OID.keyUsage, true, new asn1js.BitString({
    valueHex: new Uint8Array([0b00000110]),
    unusedBits: 1,
  }));
}

/** nameConstraints (critical): разрешаем перечисленные DNS-имена, запрещаем любые IP SAN. */
function nameConstraintsExt(domains) {
  const dns = domains.map((d) => new GeneralSubtree({ base: new GeneralName({ type: 2, value: d }) }));
  // 4/16 нулевых байтов = весь IPv4/IPv6 запрещён
  const zeroIp = (n) => new GeneralSubtree({
    base: new GeneralName({ type: 7, value: new asn1js.OctetString({ valueHex: new Uint8Array(n) }) }),
  });
  return makeExtension(OID.nameConstraints, true, new NameConstraints({
    permittedSubtrees: dns,
    excludedSubtrees: [zeroIp(4), zeroIp(16)],
  }));
}

/** SPKI-структура из CryptoKey (нужна при выпуске нового root). */
export async function publicKeyInfoFromKey(cryptoKey) {
  const spki = new PublicKeyInfo();
  await spki.importKey(cryptoKey);
  return spki;
}

/** subjectKeyIdentifier: SHA-1 от байтов открытого ключа. */
async function keyId(spki) {
  return sha1Bytes(spki.subjectPublicKey.valueBlock.valueHexView);
}

/**
 * Выпускает личный root CA (самоподписанный): критические basicConstraints
 * (pathlen 2), keyUsage, SKI и nameConstraints по списку доменов.
 * spki — SPKI ключа: свежий (publicKeyInfoFromKey) или из переиспользуемого
 * сертификата (пере выпуск на том же ключе).
 */
export async function issueRootCert({ privateKey, spki, domains, days = null }) {
  const cert = new Certificate({
    version: 2,
    serialNumber: serialNumber(),
    issuer: makeName(ROOT_SUBJECT),
    subject: makeName(ROOT_SUBJECT),
    subjectPublicKeyInfo: spki,
    ...validity(days),
    extensions: [
      makeExtension(OID.basicConstraints, true, new BasicConstraints({ cA: true, pathLenConstraint: 2 })),
      keyUsageExt(),
      makeExtension(OID.ski, false, new asn1js.OctetString({ valueHex: await keyId(spki) })),
      nameConstraintsExt(domains),
    ],
  });
  await cert.sign(privateKey, "SHA-256");
  return cert;
}

/**
 * Выпускает name-constrained proxy: носит subject и публичный ключ рута
 * минцифры, но подписан личным root; критические basicConstraints (pathlen 1),
 * keyUsage, SKI/AKI и то же nameConstraints. Оригинальный рут при этом
 * нигде не устанавливается.
 */
export async function issueProxyCert({ rootPrivateKey, rootCert, mincifryCert, domains, days = null }) {
  const cert = new Certificate({
    version: 2,
    serialNumber: serialNumber(),
    issuer: rootCert.subject,
    subject: mincifryCert.subject,
    subjectPublicKeyInfo: mincifryCert.subjectPublicKeyInfo,
    ...validity(days),
    extensions: [
      makeExtension(OID.basicConstraints, true, new BasicConstraints({ cA: true, pathLenConstraint: 1 })),
      keyUsageExt(),
      makeExtension(OID.ski, false, new asn1js.OctetString({ valueHex: await keyId(mincifryCert.subjectPublicKeyInfo) })),
      makeExtension(OID.aki, false, new AuthorityKeyIdentifier({
        keyIdentifier: new asn1js.OctetString({ valueHex: await keyId(rootCert.subjectPublicKeyInfo) }),
      })),
      nameConstraintsExt(domains),
    ],
  });
  await cert.sign(rootPrivateKey, "SHA-256");
  return cert;
}

/** Импортирует приватный ключ EC в CryptoKey; понимает PKCS#8 и SEC1. */
export async function importPrivateKey(der) {
  try {
    return await crypto.subtle.importKey("pkcs8", der, EC_PARAMS, true, ["sign"]);
  } catch {
    // SEC1 ("EC PRIVATE KEY") → пересобираем в PKCS#8 (RFC 5915 → RFC 5208)
    const ec = ECPrivateKey.fromBER(der);
    const pkcs8 = new asn1js.Sequence({
      value: [
        new asn1js.Integer({ value: 0 }),
        new asn1js.Sequence({
          value: [
            new asn1js.ObjectIdentifier({ value: OID.ecPublicKey }),
            new asn1js.ObjectIdentifier({ value: ec.namedCurve }),
          ],
        }),
        new asn1js.OctetString({ valueHex: ec.toSchema().toBER(false) }),
      ],
    }).toBER(false);
    return crypto.subtle.importKey("pkcs8", pkcs8, EC_PARAMS, true, ["sign"]);
  }
}

/**
 * Загружает сохранённый root.pem (приватный ключ + сертификат).
 * Проверяет, что сертификат — CA и ключ ему соответствует.
 * Возвращает { key, cert } для переиспользования/пере выпуска.
 */
export async function loadExistingRoot(pemText) {
  const keyBlock = pemBlocks(pemText).find((b) => b.label.includes("PRIVATE KEY"));
  if (!keyBlock || !pemBlocks(pemText).some((b) => b.label === "CERTIFICATE")) {
    throw new Error("в файле root.pem должны быть приватный ключ и сертификат");
  }
  const cert = Certificate.fromBER(pemToDer(pemText, "CERTIFICATE"));
  if (!isCA(cert)) throw new Error("сертификат в root.pem не является CA");
  const key = await importPrivateKey(base64ToBytes(keyBlock.body));
  if (!(await keyMatchesCert(key, cert))) throw new Error("ключ и сертификат в root.pem не совпадают");
  return { key, cert };
}

/** true, если basicConstraints сертификата разрешает ему быть CA. */
export function isCA(cert) {
  return !!cert.extensions?.some(
    (e) => e.extnID === OID.basicConstraints && e.parsedValue instanceof BasicConstraints && e.parsedValue.cA,
  );
}

/**
 * Расшифровывает nameConstraints сертификата: разрешённые DNS-имена и наличие
 * исключённых IPv4/IPv6 подсетей. null — расширение отсутствует.
 */
export function certNameConstraints(cert) {
  const ext = cert.extensions?.find((e) => e.extnID === OID.nameConstraints);
  if (!ext?.parsedValue) return null;
  const nc = ext.parsedValue;
  const dns = (nc.permittedSubtrees ?? [])
    .filter((st) => st.base.type === 2)
    .map((st) => st.base.value);
  let ip4 = false;
  let ip6 = false;
  for (const st of nc.excludedSubtrees ?? []) {
    const len = st.base.value?.valueBlock?.valueHexView?.length;
    if (len === 4) ip4 = true;
    if (len === 16) ip6 = true;
  }
  return { dns, ip4, ip6 };
}

/** NC сертификата покрывает весь список доменов, IP SAN запрещены? */
export function coversDomains(cert, domains) {
  const nc = certNameConstraints(cert);
  return !!nc && domains.every((d) => domainCovered(d, nc.dns)) && nc.ip4 && nc.ip6;
}

/** SHA-256 SPKI-структуры — для сравнения публичных ключей сертификатов. */
export function spkiHash(cert) {
  return sha256Hex(cert.subjectPublicKeyInfo.toSchema().toBER(false));
}

/** Проверяет, что приватный ключ соответствует публичному ключу сертификата. */
export async function keyMatchesCert(key, cert) {
  const pubKey = await cert.getPublicKey();
  const probe = new Uint8Array(32);
  crypto.getRandomValues(probe);
  const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, probe);
  return crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, pubKey, sig, probe);
}

/** Сертификат в PEM. */
export function certToPem(cert) {
  return derToPem(cert.toSchema().toBER(false), "CERTIFICATE");
}

/** Дата из validity сертификата → человекочитаемая строка UTC. */
export function formatTime(t) {
  const d = t.value;
  const p = (n) => String(n).padStart(2, "0");
  return `${d.getUTCFullYear()}-${p(d.getUTCMonth() + 1)}-${p(d.getUTCDate())} ` +
    `${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())} UTC`;
}
