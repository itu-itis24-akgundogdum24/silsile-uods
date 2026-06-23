# Blockchain Katmanı — zk-SNARK Eklemesi (Değişiklik Özeti)

Bu belge, blockchain sorumlusunun eklediği gizlilik korumalı **gerçek
zk-SNARK (Groth16)** üyelik ispatı katmanını özetler. Hakem
değerlendirmesinin asıl önerisi olan "sıfır bilgi ispatı (ZKP)" artık
yalnızca değerlendirilmemiş, **fiilen uygulanmış ve zincir üzerinde test
edilmiştir**.

## Tek cümleyle

Bir kaydın bir partiye ait olduğunu, kaydın kendisini veya ağaçtaki
konumunu **hiç ifşa etmeden**, Polygon/EVM üzerinde matematiksel olarak
kanıtlayan bir Groth16 zk-SNARK sistemi eklendi.

## Eklenen/değiştirilen dosyalar

### Yeni `zk/` paketi (saf-Python referans uygulama)
- `zk/field.py` — BN128 skaler cisim aritmetiği.
- `zk/poseidon.py` — Poseidon hash (zk-dostu; devre-içi ve düz referans birebir aynı).
- `zk/r1cs.py` — R1CS kısıt sistemi oluşturucu.
- `zk/gadgets.py` — Poseidon ve koşullu-takas (conditional swap) gadget'ları.
- `zk/circuit.py` — Merkle üyelik devresi (gizli: yaprak + yol; açık: kök).
- `zk/qap.py` — R1CS→QAP dönüşümü (hızlı Lagrange baz interpolasyonu).
- `zk/groth16.py` — Groth16 setup / prove / verify + Solidity serileştirme.
- `zk/service.py` — kurulum kalıcılaştırma, tanık (witness) inşası, prove/verify entegrasyonu.

### Sözleşmeler
- `contracts/Groth16Verifier.sol` — **YENİ.** BN128 precompile'larıyla zincir-üstü doğrulayıcı.
- `contracts/OpticalFormRegistry.sol` — `addBatchRootWithZk`, `setZkVerifier`,
  `verifyZkMembership`, `getBatchZkRoot`, `zkRootExists` eklendi. Mevcut
  `addBatchRoot` / `getBatch` / `verifyInclusion` **geriye uyumlu** korundu.
- Her iki sözleşmenin de güncel ABI + bytecode'u yeniden derlenip kaydedildi
  (resmî solc 0.8.24, sıfır uyarı).

### Entegrasyon
- `blockchain_service.py` — `send_batch_with_zk_to_chain`, `set_zk_verifier_on_chain`,
  `verify_zk_membership_on_chain`, `zk_root_exists_on_chain`.
- `offline_queue.py` — `zk_root` / `zk_proof_json` kolonları + senkronizasyon alanları.
- `app.py` — `ZK_ENABLED` ise senkronizasyonda zk kökü mühürler ve kayıt başına
  zk ispatı üretir; `/verify` ekranında zincir-üstü zk doğrulaması yapar.
- `config.py` — `ZK_ENABLED`, `ZK_DEPTH`, `ZK_KEYS_DIR`, `ZK_VERIFIER_ADDRESS`.
- `templates/verify.html` — zk doğrulama sonucu satırı.
- `scripts/generate_zk_keys.py`, `scripts/deploy_zk_verifier.py` — **YENİ** kurulum betikleri.

### Testler
- `tests/test_zk.py` — 16 birim testi (Poseidon, devre, Groth16, soundness, serileştirme).
- `tests/test_zk_onchain.py` — 3 zincir-üstü entegrasyon testi (gerçek EVM, derlenmiş sözleşme).

## Kanıtlanmış davranış

1. Python'da üretilen geçerli Groth16 ispatı, **Solidity
   `verifyZkMembership` tarafından zincir üzerinde KABUL edilir**.
2. Bozuk (tampered) ispat ve kayıtlı olmayan kök **REDDEDİLİR**.
3. Üye olmayan bir yaprak için ispat **üretilemez** (sağlamlık/soundness).
4. Eski Merkle akışının 42 testi yeni bytecode'la hâlâ geçer (geriye uyumluluk).

## Nasıl etkinleştirilir

```bash
# 1) Kurulum anahtarlarını üret (toxic waste; üretimde MPC seremonisi gerekir)
python scripts/generate_zk_keys.py --depth 10

# 2) Verifier'ı deploy et, VK'yi yükle, registry'ye bağla
python scripts/deploy_zk_verifier.py --depth 10

# 3) .env: ZK_ENABLED=true ve çıkan ZK_VERIFIER_ADDRESS değerini ekle
```

## Dürüstlük notu (jüriye karşı şeffaflık)

zk katmanı **eğitim/PoC amaçlı saf-Python** bir referans uygulamadır;
eşleşme (pairing) aritmetiği yavaştır (kurulum ve kayıt başına ispat
onlarca saniye). Demo/pilot için yeterlidir; ulusal ölçekte üretimde
snarkjs/rapidsnark gibi yerel bir prover'a geçilmelidir. Bu yüzden zk
varsayılan olarak KAPALIDIR; keccak Merkle mühürleme her zaman birincil ve
açık güvence katmanı olarak çalışır.
