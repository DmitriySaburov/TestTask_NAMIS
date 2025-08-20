#!/usr/bin/env python3
# verify_gost2012_cms.py
# Проверка CMS/PKCS#7 подписи ГОСТ Р 34.10-2012 / 34.11-2012 (detached/attached)
# Зависимости: asn1crypto==1.5.1, gostcrypto==1.2.5

import sys
import base64
from typing import Tuple, Optional, List, Iterable

from asn1crypto import cms, x509, core, pem
from gostcrypto import gosthash, gostsignature

OID_G3411_256 = "1.2.643.7.1.1.2.2"
OID_G3411_512 = "1.2.643.7.1.1.2.3"
SIG_OK_256 = {"1.2.643.7.1.1.3.2", "1.2.643.7.1.1.1.1"}
SIG_OK_512 = {"1.2.643.7.1.1.3.3", "1.2.643.7.1.1.1.2"}
OID_CT_DATA = "1.2.840.113549.1.7.1"

CURVE_TABLE_CANDIDATE_ATTRS = [
    "CURVES_R_1323565_1_024_2019",
    "CURVES_R_1323565_1_012_2018",
    "CURVES_CRYPTOPRO",
    "CURVES_RFC_4357",
    "CURVES",
]

CURVE_NAME_256_CANDIDATES = [
    "id-tc26-gost-3410-2012-256-paramSetA",
    "id-tc26-gost-3410-2012-256-paramSetB",
    "id-tc26-gost-3410-2012-256-paramSetC",
    "id-tc26-gost-3410-2012-256-paramSetD",
    "id-GostR3410-2001-CryptoPro-A-ParamSet",
    "id-GostR3410-2001-CryptoPro-B-ParamSet",
    "id-GostR3410-2001-CryptoPro-C-ParamSet",
    "id-GostR3410-2001-CryptoPro-XchA-ParamSet",
    "id-GostR3410-2001-CryptoPro-XchB-ParamSet",
]

CURVE_NAME_512_CANDIDATES = [
    "id-tc26-gost-3410-12-512-paramSetA",
    "id-tc26-gost-3410-12-512-paramSetB",
    "id-tc26-gost-3410-12-512-paramSetC",
]

def load_sig_der(sig_path: str) -> bytes:
    data = open(sig_path, "rb").read()
    if pem.detect(data):
        _t, _h, der = pem.unarmor(data)
        return der
    if data[:1] == b"\x30":
        return data
    try:
        der = base64.b64decode(data, validate=True)
        if der[:1] != b"\x30":
            raise ValueError
        return der
    except Exception:
        raise ValueError("Не удалось распознать формат .sig (ожидается CMS/PKCS#7 в DER/PEM/base64)")

def choose_hash_and_mode(si: cms.SignerInfo) -> Tuple[str, int, int]:
    dig_oid = si["digest_algorithm"]["algorithm"].dotted
    sig_oid = si["signature_algorithm"]["algorithm"].dotted
    if dig_oid == OID_G3411_256:
        if sig_oid not in SIG_OK_256:
            raise ValueError(f"Несогласованные алгоритмы: digest={dig_oid}, signature={sig_oid}")
        return "streebog256", gostsignature.MODE_256, 32
    if dig_oid == OID_G3411_512:
        if sig_oid not in SIG_OK_512:
            raise ValueError(f"Несогласованные алгоритмы: digest={dig_oid}, signature={sig_oid}")
        return "streebog512", gostsignature.MODE_512, 64
    raise ValueError(f"Неподдерживаемый digest OID: {dig_oid}")

def get_content_bytes(sd: cms.SignedData, external_pdf_path: Optional[str]) -> Tuple[bytes, str]:
    eci = sd["encap_content_info"]
    c = eci["content"]
    if c is None:
        if not external_pdf_path:
            raise ValueError("Для открепленной подписи нужно передать путь к исходному файлу")
        with open(external_pdf_path, "rb") as f:
            return f.read(), "external"
    raw = getattr(c, "contents", None) or b""
    if len(raw) == 0:
        if not external_pdf_path:
            raise ValueError("encapsulated content is empty, нужен внешний файл")
        with open(external_pdf_path, "rb") as f:
            return f.read(), "external"
    if isinstance(c, core.OctetString):
        embedded = c.native
    else:
        embedded = core.OctetString.load(raw).native if raw[0] == 0x04 else raw
    if external_pdf_path:
        with open(external_pdf_path, "rb") as f:
            ext = f.read()
        if ext != embedded:
            raise ValueError("Вложенный контент не совпал с переданным PDF (возможно, выбран не тот файл)")
    return embedded, "embedded"

def get_md_attr(si: cms.SignerInfo) -> bytes:
    attrs = si["signed_attrs"]
    if not attrs:
        raise ValueError("Нет signed_attrs")
    md = None
    ctype_ok = False
    for a in attrs:
        t = a["type"].native
        if t == "message_digest":
            md = a["values"][0].native
        elif t == "content_type":
            v = a["values"][0].native
            ctype_ok = (v == OID_CT_DATA or v == "data")
    if not ctype_ok:
        raise ValueError("signed_attrs.content_type != id-data")
    if not isinstance(md, (bytes, bytearray)):
        raise ValueError("В signed_attrs нет messageDigest")
    return md

def get_cert(sd: cms.SignedData, si: cms.SignerInfo) -> x509.Certificate:
    sid = si["sid"]
    for c in sd["certificates"] or []:
        if c.name != "certificate":
            continue
        cert = c.chosen
        tbs = cert["tbs_certificate"]
        if sid.name == "issuer_and_serial_number":
            iasn = sid.chosen
            if tbs["serial_number"].native == iasn["serial_number"].native and tbs["issuer"] == iasn["issuer"]:
                return cert
        elif sid.name == "subject_key_identifier":
            ski_sid = sid.chosen.native
            for ext in (tbs["extensions"] or []):
                if ext["extn_id"].native == "subject_key_identifier":
                    if ext["extn_value"].parsed.native == ski_sid:
                        return cert
    raise ValueError("Не найден сертификат подписанта")

def try_get_curve_by_oid(curve_oid: str):
    direct_map = {
        "1.2.643.7.1.2.1.1.1": "id-tc26-gost-3410-2012-256-paramSetA",
        "1.2.643.7.1.2.1.1.2": "id-tc26-gost-3410-2012-256-paramSetB",
        "1.2.643.7.1.2.1.1.3": "id-tc26-gost-3410-2012-256-paramSetC",
        "1.2.643.7.1.2.1.1.4": "id-tc26-gost-3410-2012-256-paramSetD",
        "1.2.643.2.2.35.1": "id-GostR3410-2001-CryptoPro-A-ParamSet",
        "1.2.643.2.2.35.2": "id-GostR3410-2001-CryptoPro-B-ParamSet",
        "1.2.643.2.2.35.3": "id-GostR3410-2001-CryptoPro-C-ParamSet",
        "1.2.643.2.2.36.0": "id-GostR3410-2001-CryptoPro-XchA-ParamSet",
        "1.2.643.2.2.36.1": "id-GostR3410-2001-CryptoPro-XchB-ParamSet",
        "1.2.643.7.1.2.1.2.1": "id-tc26-gost-3410-12-512-paramSetA",
        "1.2.643.7.1.2.1.2.2": "id-tc26-gost-3410-12-512-paramSetB",
        "1.2.643.7.1.2.1.2.3": "id-tc26-gost-3410-12-512-paramSetC",
    }
    name = direct_map.get(curve_oid)
    if not name:
        return None
    for attr in CURVE_TABLE_CANDIDATE_ATTRS:
        tbl = getattr(gostsignature, attr, None)
        if isinstance(tbl, dict) and name in tbl:
            return tbl[name]
    return None

def get_curve_candidates_for_mode(mode: int) -> List[dict]:
    names = CURVE_NAME_256_CANDIDATES if mode == gostsignature.MODE_256 else CURVE_NAME_512_CANDIDATES
    tables = []
    for attr in CURVE_TABLE_CANDIDATE_ATTRS:
        tbl = getattr(gostsignature, attr, None)
        if isinstance(tbl, dict):
            tables.append(tbl)
    found: List[dict] = []
    seen_names = set()
    for name in names:
        for tbl in tables:
            if name in tbl and name not in seen_names:
                found.append(tbl[name]); seen_names.add(name)
    if mode == gostsignature.MODE_256:
        for tbl in tables:
            for k, v in tbl.items():
                s = str(k)
                if any(t in s for t in ("XchA", "XchB")) and v not in found:
                    found.append(v)
    return found

def get_curve_and_pub(cert: x509.Certificate) -> Tuple[Optional[dict], bytes, str]:
    spki_any = cert["tbs_certificate"]["subject_public_key_info"]
    spki_seq = core.Sequence.load(spki_any.dump())
    if len(spki_seq) < 2:
        raise ValueError("Некорректный SubjectPublicKeyInfo")

    alg_seq = core.Sequence.load(spki_seq[0].dump())
    params_raw = alg_seq[1].dump() if len(alg_seq) >= 2 else b""
    if not params_raw:
        raise ValueError("algorithm.parameters отсутствуют — не удаётся определить publicKeyParamSet OID")

    if params_raw[0] == 0x06:
        curve_oid = core.ObjectIdentifier.load(params_raw).native
    elif params_raw[0] == 0x30:
        curve_oid = core.Sequence.load(params_raw)[0].native
    else:
        curve_oid = core.ObjectIdentifier.load(params_raw).native

    curve = try_get_curve_by_oid(curve_oid)  # может быть None

    pk_bitstr = core.BitString.load(spki_seq[1].dump())
    bs = pk_bitstr.contents or b""
    if len(bs) < 1:
        raise ValueError("subjectPublicKey BIT STRING пуст")
    if bs[0] != 0:
        raise ValueError(f"Ожидалось 0 unused bits, получено {bs[0]}")
    payload = bs[1:]
    if not payload:
        raise ValueError("Пустой payload в subjectPublicKey")

    if payload[0] == 0x04:
        try:
            pub = core.OctetString.load(payload).native
        except Exception:
            pub = payload
    else:
        pub = payload

    if len(pub) in (65, 129) and pub[0] == 0x00:
        pub = pub[1:]

    if len(pub) not in (64, 128):
        raise ValueError(f"Неожиданная длина публичного ключа: {len(pub)} байт (ожидалось 64 или 128)")

    return curve, pub, curve_oid

def cms_sig_to_candidates(sig: bytes, half: int) -> Iterable[bytes]:
    if len(sig) != 2 * half:
        raise ValueError("Длина подписи не соответствует размеру ключа")
    s_be, r_be = sig[:half], sig[half:]
    r_le, s_le = r_be[::-1], s_be[::-1]
    yield r_le + s_le
    yield s_le + r_le
    yield r_be + s_be
    yield s_be + r_be

def pubkey_to_candidates(pub: bytes) -> List[bytes]:
    L = len(pub)
    half = L // 2
    x, y = pub[:half], pub[half:]
    variants = [x + y, x[::-1] + y[::-1], y + x, y[::-1] + x[::-1]]
    uniq = []
    seen = set()
    for v in variants:
        if v not in seen:
            uniq.append(v); seen.add(v)
    return uniq

# NEW: варианты «что подписывали» (tbs) и как хешировать
def tbs_variants(si: cms.SignerInfo, content_bytes: bytes) -> List[Tuple[str, bytes]]:
    """
    Возвращает список (метка, bytes), где bytes — то, что могло быть подано на ГОСТ-подписание:
      - DER(signed_attrs) (стандартный CMS)        — label 'sa_der'
      - только SET без внешнего тега/длины         — label 'sa_inner'
      - исходный контент (pdf)                     — label 'content'
    """
    out = []
    sa = si["signed_attrs"]
    sa_der = sa.dump()
    out.append(("sa_der", sa_der))
    # попытаемся снять заголовок TL (tag+len) — «внутренний SET»
    try:
        header_len = sa.header_length  # у asn1crypto есть это поле
        out.append(("sa_inner", sa_der[header_len:]))
    except Exception:
        pass
    # редкий случай — подписывали сам контент
    out.append(("content", content_bytes))
    return out

def hash_variants(hname: str, data: bytes) -> List[Tuple[str, bytes]]:
    """
    Возвращает [(метка, digest)], включая реверс (LE/BE странности):
      - streebog(data)
      - reverse(streebog(data))
    """
    h = gosthash.new(hname); h.update(data)
    d = h.digest()
    return [("h", d), ("h_rev", d[::-1])]

def verify(pdf_path: str, sig_path: str) -> None:
    der = load_sig_der(sig_path)
    ci = cms.ContentInfo.load(der)
    if ci["content_type"].native != "signed_data":
        raise ValueError("В .sig не SignedData")

    sd: cms.SignedData = ci["content"]
    if len(sd["signer_infos"]) < 1:
        raise ValueError("Нет signerInfos")
    si: cms.SignerInfo = sd["signer_infos"][0]

    hname, mode, half = choose_hash_and_mode(si)
    content_bytes, source = get_content_bytes(sd, pdf_path)

    # Проверяем messageDigest(content) — обязательное условие
    md_attr = get_md_attr(si)
    h_pdf = gosthash.new(hname); h_pdf.update(content_bytes)
    if md_attr != h_pdf.digest():
        raise ValueError("messageDigest из подписи не совпал с хэшем контента (внешнего/вложенного)")

    # Сертификат и ключ
    cert = get_cert(sd, si)
    curve, pubkey_bytes, curve_oid = get_curve_and_pub(cert)

    pub_variants = pubkey_to_candidates(pubkey_bytes)

    # Список кривых к перебору
    curves_to_try: List[Tuple[str, dict]] = []
    if curve is not None:
        curves_to_try.append(("by_oid", curve))
    else:
        candidates = get_curve_candidates_for_mode(mode)
        if not candidates:
            raise ValueError(f"Не нашёл в gostcrypto подходящих кривых для режима {('256' if mode==gostsignature.MODE_256 else '512')} (OID в cert: {curve_oid})")
        curves_to_try.extend((f"candidate#{i}", cv) for i, cv in enumerate(candidates, 1))

    sig_octets: bytes = si["signature"].native

    # NEW: сформируем кандидаты на TBS и их хэши (включая реверс)
    tbs_list = tbs_variants(si, content_bytes)
    hashed_inputs: List[Tuple[str, bytes]] = []
    for tbs_tag, tbs_bytes in tbs_list:
        for h_tag, dg in hash_variants(hname, tbs_bytes):
            hashed_inputs.append((f"{tbs_tag}/{h_tag}", dg))

    verified = False
    used = {"curve": "", "pub": 0, "sig": 0, "hash": ""}

    for curve_tag, cv in curves_to_try:
        signer = gostsignature.new(mode, cv)
        for pi, pubcand in enumerate(pub_variants, 1):
            for dg_tag, dg in hashed_inputs:
                for si_idx, sigcand in enumerate(cms_sig_to_candidates(sig_octets, half), 1):
                    try:
                        # поддержим и именованные, и позиционные аргументы (разные версии gostcrypto)
                        try:
                            ok = signer.verify(pubic_key=pubcand, digest=dg, signature=sigcand)
                        except TypeError:
                            ok = signer.verify(pubcand, dg, sigcand)
                        if ok:
                            verified = True
                            used["curve"] = curve_tag
                            used["pub"] = pi
                            used["sig"] = si_idx
                            used["hash"] = dg_tag
                            break
                    except Exception:
                        pass
                if verified: break
            if verified: break
        if verified: break

    if not verified:
        raise ValueError("Криптографическая проверка не прошла ни на одной комбинации (кривая/ключ/подписанные-данные/представление подписи)")

    subj = cert.subject.human_friendly
    serial = cert.serial_number
    print("OK: подпись валидна.")
    print(f"  Источник данных: {source}")
    print(f"  Подписант: {subj}")
    print(f"  Серийный номер сертификата: {serial}")
    print(f"  publicKeyParamSet (OID из cert): {curve_oid}")
    print(f"  Хэш: {'GOST R 34.11-2012 (256)' if hname=='streebog256' else 'GOST R 34.11-2012 (512)'}")
    print(f"  Кривая: {used['curve']}")
    print(f"  Вариант публичного ключа: #{used['pub']}")
    print(f"  Что подписывали / как хэшировали: {used['hash']}")
    print(f"  Представление подписи r/s: вариант #{used['sig']}")

def main():
    if len(sys.argv) != 3:
        print("Usage: python3 verify_gost2012_cms.py <file.pdf> <signature.sig>")
        sys.exit(1)
    try:
        verify(sys.argv[1], sys.argv[2])
        sys.exit(0)
    except Exception as e:
        print(f"FAIL: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
