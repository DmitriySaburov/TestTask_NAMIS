#!/usr/bin/env python3
# diag_verify_gost2012.py
import sys, base64, traceback
from asn1crypto import cms, x509, core, pem
from gostcrypto import gosthash, gostsignature

OID_CT_DATA = "1.2.840.113549.1.7.1"
SIG_OK_256 = {"1.2.643.7.1.1.3.2", "1.2.643.7.1.1.1.1"}
SIG_OK_512 = {"1.2.643.7.1.1.3.3", "1.2.643.7.1.1.1.2"}

OID2CURVE_KEY = {
    "1.2.643.7.1.2.1.1.1": "id-tc26-gost-3410-2012-256-paramSetA",
    "1.2.643.7.1.2.1.1.2": "id-tc26-gost-3410-2012-256-paramSetB",
    "1.2.643.7.1.2.1.1.3": "id-tc26-gost-3410-2012-256-paramSetC",
    "1.2.643.7.1.2.1.1.4": "id-tc26-gost-3410-2012-256-paramSetD",
    "1.2.643.7.1.2.1.2.0": "id-tc26-gost-3410-12-512-paramSetTest",
    "1.2.643.7.1.2.1.2.1": "id-tc26-gost-3410-12-512-paramSetA",
    "1.2.643.7.1.2.1.2.2": "id-tc26-gost-3410-12-512-paramSetB",
    "1.2.643.7.1.2.1.2.3": "id-tc26-gost-3410-12-512-paramSetC",
}

# какие таблицы кривых потенциально бывают в gostcrypto.gostsignature
CURVE_TABLE_CANDIDATE_ATTRS = [
    "CURVES_R_1323565_1_024_2019",  # tc26 2012
    "CURVES_R_1323565_1_012_2018",  # cryptoPro 2001 (часто тут)
    "CURVES_RFC_4357",
    "CURVES_CRYPTOPRO",
    "CURVES",
]
# имена популярных 256-битных кривых, как их обычно называют библиотеки
CURVE_NAME_256_CANDIDATES = [
    # tc26-2012
    "id-tc26-gost-3410-2012-256-paramSetA",
    "id-tc26-gost-3410-2012-256-paramSetB",
    "id-tc26-gost-3410-2012-256-paramSetC",
    "id-tc26-gost-3410-2012-256-paramSetD",
    # CryptoPro 2001 сигнатурные
    "id-GostR3410-2001-CryptoPro-A-ParamSet",
    "id-GostR3410-2001-CryptoPro-B-ParamSet",
    "id-GostR3410-2001-CryptoPro-C-ParamSet",
    # CryptoPro 2001 «обменные» — XchA/XchB (как у вас: 1.2.643.2.2.36.0)
    "id-GostR3410-2001-CryptoPro-XchA-ParamSet",
    "id-GostR3410-2001-CryptoPro-XchB-ParamSet",
]


def dbg(*a):
    print("[dbg]", *a, flush=True)

def load_sig_der(path):
    b = open(path, "rb").read()
    dbg("sig file bytes:", len(b))
    if pem.detect(b):
        t,h,der = pem.unarmor(b)
        dbg("PEM detected:", t, "der_len=", len(der))
        return der
    if b[:1] == b"\x30":
        dbg("DER detected, starts with 0x30, len=", len(b))
        return b
    try:
        der = base64.b64decode(b, validate=True)
        if der[:1] != b"\x30":
            raise ValueError
        dbg("raw base64 detected, der_len=", len(der))
        return der
    except Exception:
        raise ValueError("Не PKCS#7/CMS DER/PEM/base64")

def choose_hash_and_mode(si):
    dig = si["digest_algorithm"]["algorithm"].dotted
    sig = si["signature_algorithm"]["algorithm"].dotted
    dbg("digest alg:", dig, "signature alg:", sig)
    if dig == "1.2.643.7.1.1.2.2":
        if sig not in SIG_OK_256:
            raise ValueError(f"Несогласованные алгоритмы: digest={dig}, signature={sig}")
        return "streebog256", gostsignature.MODE_256, 32
    if dig == "1.2.643.7.1.1.2.3":
        if sig not in SIG_OK_512:
            raise ValueError(f"Несогласованные алгоритмы: digest={dig}, signature={sig}")
        return "streebog512", gostsignature.MODE_512, 64
    raise ValueError(f"Неподдерживаемый digest OID: {dig}")

def get_content_bytes(sd: cms.SignedData, external_pdf_path: str):
    """
    Возвращает (байты_контента, источник):
      - если контент реально вложен → ("embedded")
      - если контент отсутствует ИЛИ present-but-empty → читаем внешний файл → ("external")
    """
    eci = sd["encap_content_info"]
    c = eci["content"]

    # Явно откреплённая
    if c is None:
        if not external_pdf_path:
            raise ValueError("Для открепленной подписи нужно передать путь к исходному файлу")
        with open(external_pdf_path, "rb") as f:
            return f.read(), "external"

    # Бывает "present but empty" — treat as detached
    raw = getattr(c, "contents", None) or b""
    if len(raw) == 0:
        if not external_pdf_path:
            raise ValueError("encapsulated content is empty, нужен внешний файл")
        with open(external_pdf_path, "rb") as f:
            return f.read(), "external"

    # Нормально вложенный контент
    if isinstance(c, core.OctetString):
        embedded = c.native
    else:
        # остроаккуратно: если это Any с OCTET STRING внутри
        if raw[0] == 0x04:
            embedded = core.OctetString.load(raw).native
        else:
            embedded = raw  # на всякий случай

    # если передан внешний файл — сверим идентичность (поможет поймать не тот файл)
    if external_pdf_path:
        with open(external_pdf_path, "rb") as f:
            ext = f.read()
        if ext != embedded:
            raise ValueError("Вложенный контент не совпал с переданным PDF (возможно, выбран не тот файл)")

    return embedded, "embedded"


def get_md_attr(si):
    attrs = si["signed_attrs"]
    if not attrs:
        raise ValueError("Нет signed_attrs")
    md = None; ctype_ok = False
    for a in attrs:
        t = a["type"].native
        if t == "message_digest": md = a["values"][0].native
        elif t == "content_type":
            v = a["values"][0].native
            ctype_ok = (v == OID_CT_DATA or v == "data")
    if not ctype_ok: raise ValueError("content_type != id-data")
    if not isinstance(md, (bytes, bytearray)): raise ValueError("нет messageDigest")
    dbg("messageDigest len:", len(md))
    return md

def get_cert(sd, si):
    sid = si["sid"]
    dbg("signer sid type:", sid.name)
    for c in sd["certificates"] or []:
        if c.name != "certificate": continue
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

def get_curve_and_pub(cert):
    """
    Возвращает (curve, pub_x_y_le_bytes, curve_oid) из SubjectPublicKeyInfo.
    ВАЖНО: не обращаемся к spki["algorithm"] по имени — парсим SPKI как core.Sequence.
    """
    from asn1crypto import core
    spki_any = cert["tbs_certificate"]["subject_public_key_info"]

    # SPKI ::= SEQUENCE { algorithm AlgorithmIdentifier, subjectPublicKey BIT STRING }
    spki_seq = core.Sequence.load(spki_any.dump())
    if len(spki_seq) < 2:
        raise ValueError("Некорректный SubjectPublicKeyInfo")

    # --- AlgorithmIdentifier (SEQUENCE { OID, params OPTIONAL }) без спеков asn1crypto
    alg_seq = core.Sequence.load(spki_seq[0].dump())
    # params могут отсутствовать; для ГОСТ обычно есть и содержат publicKeyParamSet
    if len(alg_seq) >= 2:
        params_raw = alg_seq[1].dump()
    else:
        params_raw = b""

    if not params_raw:
        raise ValueError("algorithm.parameters отсутствуют — не удаётся определить publicKeyParamSet OID")

    # parameters: либо OID (0x06), либо SEQUENCE(publicKeyParamSet, ...)
    if params_raw[0] == 0x06:
        curve_oid = core.ObjectIdentifier.load(params_raw).native
    elif params_raw[0] == 0x30:
        curve_oid = core.Sequence.load(params_raw)[0].native
    else:
        # пробуем как OID «на всякий»
        curve_oid = core.ObjectIdentifier.load(params_raw).native

    curve_key = OID2CURVE_KEY.get(curve_oid)
    if not curve_key:
        raise ValueError(f"Неизвестная кривая/параметры: {curve_oid}")
    curve = gostsignature.CURVES_R_1323565_1_024_2019[curve_key]

    # --- subjectPublicKey (BIT STRING)
    pk_bitstr = core.BitString.load(spki_seq[1].dump())
    bs = pk_bitstr.contents or b""
    if len(bs) < 1:
        raise ValueError("subjectPublicKey BIT STRING пуст")
    if bs[0] != 0:
        raise ValueError(f"Ожидалось 0 unused bits, получено {bs[0]}")
    payload = bs[1:]
    if not payload:
        raise ValueError("Пустой payload в subjectPublicKey")

    # Вариант A: OCTET STRING(x||y), Вариант B: raw x||y
    if payload[0] == 0x04:
        try:
            pub = core.OctetString.load(payload).native
        except Exception:
            pub = payload
    else:
        pub = payload

    # Возможный ведущий ноль-паддинг (65/129 байт)
    if len(pub) in (65, 129) and pub[0] == 0x00:
        pub = pub[1:]

    if len(pub) not in (64, 128):
        raise ValueError(f"Неожиданная длина публичного ключа: {len(pub)} (ожидалось 64 или 128 байт)")

    return curve, pub, curve_oid



def cms_sig_candidates(sig, half):
    s_be, r_be = sig[:half], sig[half:]
    r_le, s_le = r_be[::-1], s_be[::-1]
    return [r_le + s_le, s_le + r_le, r_be + s_be, s_be + r_be]

def main(pdf_path, sig_path):
    print("[dbg] start", flush=True)
    try:
        der = load_sig_der(sig_path)
        dbg("der len:", len(der))
        ci = cms.ContentInfo.load(der)
        if ci["content_type"].native != "signed_data":
            raise ValueError("Не SignedData")
        sd = ci["content"]
        if len(sd["signer_infos"]) < 1:
            raise ValueError("Нет signerInfos")
        si = sd["signer_infos"][0]

        hname, mode, half = choose_hash_and_mode(si)
        content, src = get_content_bytes(sd, pdf_path)
        dbg("content bytes:", src, len(content))

        md_attr = get_md_attr(si)
        h = gosthash.new(hname); h.update(content)
        if md_attr != h.digest():
            raise ValueError("messageDigest != hash(content)")

        sa_der = si["signed_attrs"].dump()
        dbg("signed_attrs der len:", len(sa_der))
        h2 = gosthash.new(hname); h2.update(sa_der)
        dgst = h2.digest()

        cert = get_cert(sd, si)
        subj = cert.subject.human_friendly
        dbg("cert subject:", subj)
        curve, pub, curve_oid = get_curve_and_pub(cert)

        sig_oct = si["signature"].native
        dbg("sig len:", len(sig_oct))
        sign = gostsignature.new(mode, curve)
        for i, cand in enumerate(cms_sig_candidates(sig_oct, half), 1):
            ok = False
            try:
                ok = sign.verify(pub, dgst, cand)
            except Exception as e:
                dbg(f"verify variant #{i} raised:", repr(e))
            if ok:
                print("OK: подпись валидна.")
                return
        raise ValueError("Не прошла криптопроверка ни в одном представлении r/s")
    except Exception as e:
        print("FAIL:", e, file=sys.stderr)
        traceback.print_exc(limit=4, file=sys.stderr)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python diag_verify_gost2012.py <file.pdf> <signature.sig>")
        sys.exit(1)
    main(sys.argv[1], sys.argv[2])
