from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from eth_account import Account  # noqa: E402
from web3 import Web3  # noqa: E402
from web3.exceptions import TimeExhausted  # noqa: E402

from config import config  # noqa: E402
from zk.service import DEFAULT_DEPTH, export_vk_for_contract, load_setup  # noqa: E402

CONTRACTS_DIR = Path(__file__).resolve().parent.parent / "contracts"


def _fail(msg: str) -> None:
    print(f"\n[HATA] {msg}\n", file=sys.stderr)
    sys.exit(1)


def _load_artifact(name: str):
    abi = json.loads((CONTRACTS_DIR / f"{name}.abi.json").read_text(encoding="utf-8"))
    bytecode = (CONTRACTS_DIR / f"{name}.bytecode.txt").read_text(encoding="utf-8").strip()
    if not bytecode.startswith("0x"):
        bytecode = "0x" + bytecode
    return abi, bytecode


def _send(w3, account, tx, chain_id):
    nonce = w3.eth.get_transaction_count(account.address, "pending")
    tx.update(
        {
            "from": account.address,
            "nonce": nonce,
            "chainId": chain_id,
            "maxPriorityFeePerGas": w3.to_wei(config.MAX_PRIORITY_FEE_GWEI, "gwei"),
            "maxFeePerGas": w3.to_wei(config.MAX_FEE_GWEI, "gwei"),
        }
    )
    signed = account.sign_transaction(tx)
    h = w3.eth.send_raw_transaction(signed.raw_transaction)
    receipt = w3.eth.wait_for_transaction_receipt(h, timeout=180)
    if receipt.status != 1:
        _fail(f"Islem revert oldu: 0x{h.hex().lstrip('0x')}")
    return receipt


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Groth16Verifier sozlesmesini dagitir, VK'yi yukler ve "
        "registry'ye baglar."
    )
    parser.add_argument("--depth", type=int, default=DEFAULT_DEPTH)
    parser.add_argument(
        "--keys",
        type=str,
        default=str(Path(__file__).resolve().parent.parent / "instance" / "zk_keys"),
    )
    parser.add_argument(
        "--lock",
        action="store_true",
        help="VK yuklendikten sonra dogrulama anahtarini kalici olarak kilitler.",
    )
    args = parser.parse_args()

    if not config.POLYGON_RPC_URL:
        _fail("POLYGON_RPC_URL tanimli degil.")
    if not config.INSTITUTION_PRIVATE_KEY or config.INSTITUTION_PRIVATE_KEY.startswith("0xBU_DEGERI"):
        _fail("INSTITUTION_PRIVATE_KEY tanimli degil.")
    if not config.CONTRACT_ADDRESS or config.CONTRACT_ADDRESS == "0x0000000000000000000000000000000000000000":
        _fail("CONTRACT_ADDRESS tanimli degil (once OpticalFormRegistry deploy edilmeli).")

    zk_setup = load_setup(args.keys, depth=args.depth)
    if zk_setup is None:
        _fail(
            f"zk anahtarlari bulunamadi ({args.keys}). Once "
            "'python scripts/generate_zk_keys.py' calistirin."
        )

    w3 = Web3(Web3.HTTPProvider(config.POLYGON_RPC_URL, request_kwargs={"timeout": 30}))
    if not w3.is_connected():
        _fail(f"RPC'ye baglanilamadi: {config.POLYGON_RPC_URL}")
    account = Account.from_key(config.INSTITUTION_PRIVATE_KEY)
    chain_id = config.POLYGON_CHAIN_ID
    print(f"Cuzdan: {account.address}")
    print(f"Bakiye: {w3.from_wei(w3.eth.get_balance(account.address), 'ether')} POL")

    ver_abi, ver_bytecode = _load_artifact("Groth16Verifier")
    Verifier = w3.eth.contract(abi=ver_abi, bytecode=ver_bytecode)
    print("\nGroth16Verifier dagitiliyor...")
    receipt = _send(w3, account, Verifier.constructor().build_transaction({}), chain_id)
    verifier_address = receipt.contractAddress
    print(f"Verifier adresi: {verifier_address}")

    verifier = w3.eth.contract(address=verifier_address, abi=ver_abi)
    vk = export_vk_for_contract(zk_setup)
    print("Dogrulama anahtari (VK) zincire yukleniyor...")
    _send(
        w3,
        account,
        verifier.functions.setVerifyingKey(
            vk["alpha"], vk["beta"], vk["gamma"], vk["delta"], vk["ic"]
        ).build_transaction({}),
        chain_id,
    )
    print(f"VK yuklendi, ic uzunlugu: {verifier.functions.icLength().call()}")

    if args.lock:
        _send(w3, account, verifier.functions.lockVerifyingKey().build_transaction({}), chain_id)
        print("VK kalici olarak kilitlendi.")

    reg_abi, _ = _load_artifact("OpticalFormRegistry")
    registry = w3.eth.contract(
        address=Web3.to_checksum_address(config.CONTRACT_ADDRESS), abi=reg_abi
    )
    print("Registry, verifier adresine baglaniyor (setZkVerifier)...")
    _send(w3, account, registry.functions.setZkVerifier(verifier_address).build_transaction({}), chain_id)
    print(f"registry.zkVerifier = {registry.functions.zkVerifier().call()}")

    info = {
        "verifier_address": verifier_address,
        "registry_address": config.CONTRACT_ADDRESS,
        "depth": args.depth,
        "chain_id": chain_id,
        "deployed_at_unix": int(time.time()),
    }
    (CONTRACTS_DIR / "zk_deployment_info.json").write_text(
        json.dumps(info, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    print("\nBilgi kaydedildi: contracts/zk_deployment_info.json")
    print(f"\n.env dosyaniza ekleyin:\n  ZK_VERIFIER_ADDRESS={verifier_address}\n")


if __name__ == "__main__":
    main()
