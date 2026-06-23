// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

library Pairing {
    struct G1Point {
        uint256 X;
        uint256 Y;
    }

    struct G2Point {
        uint256[2] X;
        uint256[2] Y;
    }

    function P1() internal pure returns (G1Point memory) {
        return G1Point(1, 2);
    }

    function P2() internal pure returns (G2Point memory) {
        return
            G2Point(
                [
                    11559732032986387107991004021392285783925812861821192530917403151452391805634,
                    10857046999023057135944570762232829481370756359578518086990519993285655852781
                ],
                [
                    4082367875863433681332203403145435568316851327593401208105741076214120093531,
                    8495653923123431417604973247489272438418190587263600148770280649306958101930
                ]
            );
    }

    function negate(G1Point memory p) internal pure returns (G1Point memory) {
        uint256 q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
        if (p.X == 0 && p.Y == 0) {
            return G1Point(0, 0);
        }
        return G1Point(p.X, q - (p.Y % q));
    }

    function addition(G1Point memory p1, G1Point memory p2)
        internal
        view
        returns (G1Point memory r)
    {
        uint256[4] memory input;
        input[0] = p1.X;
        input[1] = p1.Y;
        input[2] = p2.X;
        input[3] = p2.Y;
        bool success;
        assembly {
            success := staticcall(gas(), 6, input, 0xc0, r, 0x60)
        }
        require(success, "ecAdd basarisiz");
    }

    function scalar_mul(G1Point memory p, uint256 s)
        internal
        view
        returns (G1Point memory r)
    {
        uint256[3] memory input;
        input[0] = p.X;
        input[1] = p.Y;
        input[2] = s;
        bool success;
        assembly {
            success := staticcall(gas(), 7, input, 0x80, r, 0x60)
        }
        require(success, "ecMul basarisiz");
    }

    function pairing(G1Point[] memory p1, G2Point[] memory p2)
        internal
        view
        returns (bool)
    {
        require(p1.length == p2.length, "esit uzunluk gerekli");
        uint256 elements = p1.length;
        uint256 inputSize = elements * 6;
        uint256[] memory input = new uint256[](inputSize);
        for (uint256 i = 0; i < elements; i++) {
            input[i * 6 + 0] = p1[i].X;
            input[i * 6 + 1] = p1[i].Y;
            input[i * 6 + 2] = p2[i].X[0];
            input[i * 6 + 3] = p2[i].X[1];
            input[i * 6 + 4] = p2[i].Y[0];
            input[i * 6 + 5] = p2[i].Y[1];
        }
        uint256[1] memory out;
        bool success;
        assembly {
            success := staticcall(
                gas(),
                8,
                add(input, 0x20),
                mul(inputSize, 0x20),
                out,
                0x20
            )
        }
        require(success, "ecPairing basarisiz");
        return out[0] != 0;
    }
}

contract Groth16Verifier {
    using Pairing for *;

    struct VerifyingKey {
        Pairing.G1Point alpha;
        Pairing.G2Point beta;
        Pairing.G2Point gamma;
        Pairing.G2Point delta;
        Pairing.G1Point[] ic;
    }

    struct Proof {
        Pairing.G1Point a;
        Pairing.G2Point b;
        Pairing.G1Point c;
    }

    uint256 internal constant SNARK_SCALAR_FIELD =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    Pairing.G1Point internal vkAlpha;
    Pairing.G2Point internal vkBeta;
    Pairing.G2Point internal vkGamma;
    Pairing.G2Point internal vkDelta;
    Pairing.G1Point[] internal vkIC;

    address public owner;
    bool public keyLocked;

    error SadeceSahip();
    error AnahtarKilitli();
    error GecersizGiris();

    event VerifyingKeySet(uint256 icLength);
    event VerifyingKeyLocked();

    modifier onlyOwner() {
        if (msg.sender != owner) revert SadeceSahip();
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function setVerifyingKey(
        uint256[2] calldata alpha,
        uint256[2][2] calldata beta,
        uint256[2][2] calldata gamma,
        uint256[2][2] calldata delta,
        uint256[2][] calldata ic
    ) external onlyOwner {
        if (keyLocked) revert AnahtarKilitli();
        vkAlpha = Pairing.G1Point(alpha[0], alpha[1]);
        vkBeta = Pairing.G2Point([beta[0][0], beta[0][1]], [beta[1][0], beta[1][1]]);
        vkGamma = Pairing.G2Point([gamma[0][0], gamma[0][1]], [gamma[1][0], gamma[1][1]]);
        vkDelta = Pairing.G2Point([delta[0][0], delta[0][1]], [delta[1][0], delta[1][1]]);
        delete vkIC;
        for (uint256 i = 0; i < ic.length; i++) {
            vkIC.push(Pairing.G1Point(ic[i][0], ic[i][1]));
        }
        emit VerifyingKeySet(ic.length);
    }

    function lockVerifyingKey() external onlyOwner {
        keyLocked = true;
        emit VerifyingKeyLocked();
    }

    function icLength() external view returns (uint256) {
        return vkIC.length;
    }

    function verifyProof(
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint256[] calldata publicInputs
    ) public view returns (bool) {
        if (publicInputs.length + 1 != vkIC.length) revert GecersizGiris();

        Pairing.G1Point memory vkX = vkIC[0];
        for (uint256 i = 0; i < publicInputs.length; i++) {
            if (publicInputs[i] >= SNARK_SCALAR_FIELD) revert GecersizGiris();
            vkX = Pairing.addition(
                vkX,
                Pairing.scalar_mul(vkIC[i + 1], publicInputs[i])
            );
        }

        Pairing.G1Point memory negA = Pairing.negate(Pairing.G1Point(a[0], a[1]));

        Pairing.G1Point[] memory p1 = new Pairing.G1Point[](4);
        Pairing.G2Point[] memory p2 = new Pairing.G2Point[](4);

        p1[0] = negA;
        p2[0] = Pairing.G2Point([b[0][0], b[0][1]], [b[1][0], b[1][1]]);

        p1[1] = vkAlpha;
        p2[1] = vkBeta;

        p1[2] = vkX;
        p2[2] = vkGamma;

        p1[3] = Pairing.G1Point(c[0], c[1]);
        p2[3] = vkDelta;

        return Pairing.pairing(p1, p2);
    }
}
