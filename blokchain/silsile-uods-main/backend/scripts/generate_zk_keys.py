from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from zk.service import DEFAULT_DEPTH, generate_zk_setup, save_setup


def main() -> None:
    parser = argparse.ArgumentParser(
        description="UODS zk-SNARK (Groth16) kurulum anahtarlarini uretir ve diske kaydeder."
    )
    parser.add_argument(
        "--depth",
        type=int,
        default=DEFAULT_DEPTH,
        help=f"Merkle agac derinligi (varsayilan {DEFAULT_DEPTH}; kapasite 2**depth kayit).",
    )
    parser.add_argument(
        "--out",
        type=str,
        default=str(Path(__file__).resolve().parent.parent / "instance" / "zk_keys"),
        help="Anahtarlarin kaydedilecegi dizin.",
    )
    args = parser.parse_args()

    print("=" * 70)
    print(f"UODS — zk-SNARK kurulumu (Groth16, BN128, derinlik={args.depth})")
    print("=" * 70)
    print(
        "\nUYARI: Bu kurulum bir 'toxic waste' (tau, alpha, beta, gamma, delta)\n"
        "uretir; uretim ortaminda bu degerler bellekte kalmamali ve cok-tarafli\n"
        "bir guvenilir kurulum (MPC ceremony) ile uretilmelidir. Bu betik tek\n"
        "makineli referans kurulumdur.\n"
    )

    t = time.time()
    zk_setup = generate_zk_setup(depth=args.depth)
    print(f"Kurulum uretildi: {round(time.time() - t, 1)} s")

    pk_path, vk_path = save_setup(zk_setup, args.out)
    print(f"Proving key  : {pk_path}")
    print(f"Verifying key: {vk_path}")
    print(f"VK ic uzunlugu: {len(zk_setup.verifying_key.ic)} (numPublic={zk_setup.verifying_key.num_public})")
    print(
        "\nSonraki adim: 'python scripts/deploy_zk_verifier.py' ile Groth16Verifier\n"
        "sozlesmesini dagitip bu VK'yi zincire yukleyin.\n"
    )


if __name__ == "__main__":
    main()
