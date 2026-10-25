// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {CA} from "../Common.sol";
import {PCKHelper, X509CertObj} from "../helpers/PCKHelper.sol";
import {X509Helper} from "../helpers/X509Helper.sol";
import {X509CRLHelper, X509CRLObj} from "../helpers/X509CRLHelper.sol";

import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import {LibString} from "solady/utils/LibString.sol";

import {PcsDao} from "./PcsDao.sol";
import {DaoBase} from "./DaoBase.sol";
import {SigVerifyBase} from "./SigVerifyBase.sol";

/// @notice the schema of the attested data for PCK Certs is simply DER-encoded form of the X509
/// @notice Certificate stored in bytes

/**
 * @title Intel PCK Certificate Data Access Object
 * @notice This contract is heavily inspired by Sections 4.2.2, 4.2.4 and 4.2.8 in the Intel SGX PCCS Design Guideline
 * https://download.01.org/intel-sgx/sgx-dcap/1.19/linux/docs/SGX_DCAP_Caching_Service_Design_Guide.pdf
 * @notice This contract is the combination of both PckDao and PlatformTcbsDao as described in section 4.2
 */
abstract contract PckDao is DaoBase, SigVerifyBase {
    using EnumerableSet for EnumerableSet.Bytes32Set;

    // first 4 bytes of keccak256('PCK_MAGIC')
    bytes4 constant PCK_MAGIC = 0xf0e2a246;
    // first 4 bytes of keccak256('TCB_MAPPING_MAGIC')
    bytes4 constant TCB_MAPPING_MAGIC = 0x5b8e7b4e;

    // 167c231a
    error Certificate_Revoked(uint256 serialNum);
    // dba942a2
    error Certificate_Expired();
    // 1e7ab599
    error Invalid_Issuer_Name();
    // 92ec707e
    error Invalid_Subject_Name();
    // e6612a12
    error Expired_Certificates();
    // 4a629e24
    error TCB_Mismatch();
    // cd69d374
    error Missing_Issuer();
    // a7ee790d
    error Issuer_Expired(CA ca);
    // f465bfb2
    error Issuer_Revoked(CA ca, uint256 serialNum);
    // e7ef341f
    error Invalid_Signature();

    /// @notice the input CA parameter can only be either PROCESSOR or PLATFORM
    // 9849e774
    error Invalid_PCK_CA(CA ca);
    /// @notice The corresponding PCK Certificate cannot be found for the given platform
    // 82fba295
    error Pck_Not_Found();

    // bf00a30d
    error Pck_Out_Of_Date();

    // 55910199
    error Invalid_Qeid_Length();
    // 9502e28d
    error Invalid_Pceid_Length();
    // 03a471a6
    error Invalid_Platform_Cpu_Svn_Length();
    // ad582778
    error Invalid_Platform_Pce_Svn_Length();
    // 3d07e1f3
    error Invalid_Tcbm_Length();

    event UpsertedPckCollateral(CA indexed ca, bytes16 indexed qeid, bytes2 indexed pceid, bytes18 tcbm);

    event UpsertPlatformTcb(
        bytes16 indexed qeid, bytes2 indexed pceid, bytes16 platformCpuSvn, bytes2 platformPceSvn, bytes18 tcbm
    );

    string constant PCK_PLATFORM_CA_COMMON_NAME = "Intel SGX PCK Platform CA";
    string constant PCK_PROCESSOR_CA_COMMON_NAME = "Intel SGX PCK Processor CA";
    string constant PCK_COMMON_NAME = "Intel SGX PCK Certificate";

    PcsDao public Pcs;
    PCKHelper public pckLib;
    X509CRLHelper public crlLib;

    modifier pckCACheck(CA ca) {
        if (ca == CA.ROOT || ca == CA.SIGNING) {
            revert Invalid_PCK_CA(ca);
        }
        _;
    }

    constructor(address _resolver, address _p256, address _pcs, address _x509, address _crl)
        SigVerifyBase(_p256, _x509)
        DaoBase(_resolver)
    {
        Pcs = PcsDao(_pcs);
        pckLib = PCKHelper(_x509);
        crlLib = X509CRLHelper(_crl);
    }

    function PCK_KEY(bytes16 qeidBytes, bytes2 pceidBytes, bytes18 tcbmBytes) public pure returns (bytes32 key) {
        key = keccak256(abi.encodePacked(PCK_MAGIC, qeidBytes, pceidBytes, tcbmBytes));
    }

    function TCB_MAPPING_KEY(bytes16 qeid, bytes2 pceid, bytes16 platformCpuSvn, bytes2 platformPceSvn)
        public
        pure
        returns (bytes32 key)
    {
        key = keccak256(abi.encodePacked(TCB_MAPPING_MAGIC, qeid, pceid, platformCpuSvn, platformPceSvn));
    }

    function getCollateralValidity(bytes32 key)
        external
        view
        override
        returns (uint64 notValidBefore, uint64 notValidAfter)
    {
        (notValidBefore, notValidAfter) = _loadPckValidity(key);
    }

    /**
     * @notice Section 4.2.2 (getCert(qe_id, cpu_svn, pce_svn, pce_id))
     */
    function getCert(
        string calldata qeid,
        string calldata platformCpuSvn,
        string calldata platformPceSvn,
        string calldata pceid
    ) external view returns (bytes memory pckCert) {
        (bytes16 qeidBytes, bytes2 pceidBytes) = _parseQeidAndPceid(qeid, pceid);
        (bytes16 platformCpuSvnBytes, bytes2 platformPceSvnBytes) =
            _parsePlatformSvns(platformCpuSvn, platformPceSvn);
        bytes18 tcbmBytes =
            _tcbrToTcbmMapping(TCB_MAPPING_KEY(qeidBytes, pceidBytes, platformCpuSvnBytes, platformPceSvnBytes));
        if (tcbmBytes != bytes18(0)) {
            pckCert = _onFetchDataFromResolver(PCK_KEY(qeidBytes, pceidBytes, tcbmBytes), false);
        }
    }

    function getCerts(string calldata qeid, string calldata pceid)
        external
        view
        returns (string[] memory tcbms, bytes[] memory pckCerts)
    {
        (bytes16 qeidBytes, bytes2 pceidBytes) = _parseQeidAndPceid(qeid, pceid);

        bytes18[] memory tcbmBytes = _getAllTcbs(qeidBytes, pceidBytes);
        uint256 n = tcbmBytes.length;
        if (n > 0) {
            tcbms = new string[](n);
            pckCerts = new bytes[](n);

            for (uint256 i = 0; i < n;) {
                tcbms[i] = LibString.toHexStringNoPrefix(abi.encodePacked(tcbmBytes[i]));
                pckCerts[i] = _onFetchDataFromResolver(PCK_KEY(qeidBytes, pceidBytes, tcbmBytes[i]), false);

                unchecked {
                    i++;
                }
            }
        }
    }

    /**
     * @notice Modified from Section 4.2.8 (getPlatformTcbsById)
     * @notice Fetches the mapping for the input raw TCB to an attested tcbm
     */
    function getPlatformTcbByIdAndSvns(
        string calldata qeid,
        string calldata pceid,
        string calldata platformCpuSvn,
        string calldata platformPceSvn
    ) external view returns (string memory tcbm) {
        (bytes16 qeidBytes, bytes2 pceidBytes) = _parseQeidAndPceid(qeid, pceid);
        (bytes16 platformCpuSvnBytes, bytes2 platformPceSvnBytes) =
            _parsePlatformSvns(platformCpuSvn, platformPceSvn);
        bytes18 tcbmBytes =
            _tcbrToTcbmMapping(TCB_MAPPING_KEY(qeidBytes, pceidBytes, platformCpuSvnBytes, platformPceSvnBytes));
        if (tcbmBytes != bytes18(0)) {
            tcbm = LibString.toHexStringNoPrefix(abi.encodePacked(tcbmBytes));
        }
    }

    /**
     * @notice Modified from Section 4.2.2 (upsertPckCert)
     * @notice This method requires an additional CA parameter, because the on-chain PCCS does not
     * store any data that is contained in the PLATFORMS table.
     * @notice Therefore, there is no way to form a mapping between (qeid, pceid) to its corresponding CA.
     * @param cert DER-encoded PCK Leaf Certificate
     */
    function upsertPckCert(
        CA ca,
        string calldata qeid,
        string calldata pceid,
        string calldata tcbm,
        bytes calldata cert
    ) external pckCACheck(ca) returns (bytes32 attestationId) {
        (bytes16 qeidBytes, bytes2 pceidBytes) = _parseQeidAndPceid(qeid, pceid);
        bytes18 tcbmBytes = _parseTcbm(tcbm);
        (bytes32 hash, bytes32 key, X509CertObj memory pck) = _validatePck(ca, cert, qeidBytes, pceidBytes, tcbmBytes);

        // attest timestamp
        _storePckValidity(key, uint64(pck.validityNotBefore), uint64(pck.validityNotAfter));

        attestationId = _attestPck(cert, hash, key);
        _upsertTcbm(qeidBytes, pceidBytes, tcbmBytes);

        emit UpsertedPckCollateral(ca, qeidBytes, pceidBytes, tcbmBytes);
    }

    /**
     * @notice this method creates a mapping for raw TCB values to a "known" TCBm svns
     * @notice this contract does not provide implementation for determining the best tcbm for
     * the given raw TCB values
     * @dev should override the _setTcbrToTcbmMapping() method
     * to implement their own tcbm selection implementation
     * @dev this function does not require for explicit attestations, but implementers may implement one
     * if necessary.
     */
    function upsertPlatformTcbs(
        string calldata qeid,
        string calldata pceid,
        string calldata platformCpuSvn,
        string calldata platformPceSvn,
        string calldata tcbm
    ) external returns (bytes32) {
        (bytes16 qeidBytes, bytes2 pceidBytes) = _parseQeidAndPceid(qeid, pceid);
        (bytes16 platformCpuSvnBytes, bytes2 platformPceSvnBytes) =
            _parsePlatformSvns(platformCpuSvn, platformPceSvn);
        bytes18 tcbmBytes = _parseTcbm(tcbm);

        bytes32 pckKey = PCK_KEY(qeidBytes, pceidBytes, tcbmBytes);

        bytes memory der = _fetchDataFromResolver(pckKey, false);
        if (der.length == 0) {
            revert Pck_Not_Found();
        }

        // parse PCK to check for whether the provided PCEID and tcbm values are valid
        X509CertObj memory pck = pckLib.parseX509DER(der);
        _validatePckTcb(pceidBytes, tcbmBytes, der, pck.extensionPtr);

        bytes32 tcbmMappingKey = TCB_MAPPING_KEY(qeidBytes, pceidBytes, platformCpuSvnBytes, platformPceSvnBytes);
        _setTcbrToTcbmMapping(tcbmMappingKey, tcbmBytes);

        emit UpsertPlatformTcb(qeidBytes, pceidBytes, platformCpuSvnBytes, platformPceSvnBytes, tcbmBytes);

        return bytes32(0);
    }

    /**
     * Queries PCK Certificate issuer chain for the input ca.
     * @param ca is either CA.PROCESSOR (uint8(1)) or CA.PLATFORM ((uint8(2)))
     * @return intermediateCert - the corresponding intermediate PCK CA (DER-encoded)
     * @return rootCert - Intel SGX Root CA (DER-encoded)
     */
    function getPckCertChain(CA ca)
        external
        view
        pckCACheck(ca)
        returns (bytes memory intermediateCert, bytes memory rootCert)
    {
        intermediateCert = _onFetchDataFromResolver(Pcs.PCS_KEY(ca, false), false);
        rootCert = _onFetchDataFromResolver(Pcs.PCS_KEY(CA.ROOT, false), false);
    }

    /**
     * @notice attests collateral via the Resolver
     * @return attestationId
     */
    function _attestPck(bytes memory reqData, bytes32 hash, bytes32 key)
        internal
        virtual
        returns (bytes32 attestationId)
    {
        (attestationId,) = resolver.attest(key, reqData, hash);
    }

    /**
     * @dev hook that can be called after the tcbm has been verified by a PCK Certificate issued
     * for the given qeid and pceid
     * @dev this is essential for creating a (qeid, pceid) => tcbm association
     */
    function _upsertTcbm(bytes16 qeid, bytes2 pceid, bytes18 tcbm) internal virtual;

    /**
     * @dev this is essential for creating a (qeid, pceid, raw tcb) => tcbm association
     */
    function _setTcbrToTcbmMapping(bytes32 tcbMappingKey, bytes18 tcbmBytes) internal virtual;

    /**
     * @dev return bytes18(0) if tcbm not found
     */
    function _tcbrToTcbmMapping(bytes32 tcbMappingKey) internal view virtual returns (bytes18 tcbm);

    /**
     * @notice fetches all tcbm bytes associated with the given qeid and pceid
     * @notice tcbm is a 18-byte data which is a concatenation of PCK cpusvn (16 bytes) and pcesvn (2 bytes)
     */
    function _getAllTcbs(bytes16 qeidBytes, bytes2 pceidBytes) internal view virtual returns (bytes18[] memory tcbms);

    function _validatePck(CA ca, bytes memory der, bytes16 qeid, bytes2 pceid, bytes18 tcbm)
        internal
        view
        returns (bytes32 hash, bytes32 key, X509CertObj memory pck)
    {
        pck = pckLib.parseX509DER(der);

        hash = keccak256(pck.tbs);
        key = PCK_KEY(qeid, pceid, tcbm);

        // Step 0: Check whether the certificate has been previously attested
        _checkCollateralDuplicate(key, hash);

        // Step 1: Check whether the pck has expired
        bool notExpired = block.timestamp > pck.validityNotBefore && block.timestamp < pck.validityNotAfter;
        if (!notExpired) {
            revert Certificate_Expired();
        }

        // Step 2: Rollback prevention: new certificate should not have an issued date
        // that is older than the existing certificate
        (uint64 existingCertNotValidBefore,) = _loadPckValidity(key);
        bool outOfDate = existingCertNotValidBefore >= pck.validityNotBefore;
        if (outOfDate) {
            revert Pck_Out_Of_Date();
        }

        // Step 3: Check Issuer and Subject names
        string memory expectedIssuer;
        if (ca == CA.PLATFORM) {
            expectedIssuer = PCK_PLATFORM_CA_COMMON_NAME;
        } else if (ca == CA.PROCESSOR) {
            expectedIssuer = PCK_PROCESSOR_CA_COMMON_NAME;
        }
        if (!LibString.eq(pck.issuerCommonName, expectedIssuer)) {
            revert Invalid_Issuer_Name();
        }
        if (!LibString.eq(pck.subjectCommonName, PCK_COMMON_NAME)) {
            revert Invalid_Subject_Name();
        }

        // Step 4: validate PCEID and TCBm
        _validatePckTcb(pceid, tcbm, der, pck.extensionPtr);

        // Step 5: Check whether the pck has been revoked
        bytes memory crlData = _fetchDataFromResolver(Pcs.PCS_KEY(ca, true), false);
        if (crlData.length > 0) {
            bool revocable = crlLib.serialNumberIsRevoked(pck.serialNumber, crlData);
            if (revocable) {
                revert Certificate_Revoked(pck.serialNumber);
            }
        }

        // Step 5: Check signature against issuer certificate
        bytes32 issuerKey = Pcs.PCS_KEY(ca, false);
        (uint256 notBefore, uint256 notAfter) = Pcs.getCollateralValidity(issuerKey);
        if (block.timestamp < notBefore || block.timestamp > notAfter) {
            revert Issuer_Expired(ca);
        }
        bytes memory issuerCert = _fetchDataFromResolver(issuerKey, false);
        if (issuerCert.length > 0) {
            // check issuer evocation status
            bytes memory rootCrl = _fetchDataFromResolver(Pcs.PCS_KEY(CA.ROOT, true), false);
            if (rootCrl.length > 0) {
                // the root CRL lists the serial numbers of the revoked CA certificates and not
                // the serial numbers of the leaf certificates, so the serial number of the
                // issuer certificate has to be checked against it
                uint256 issuerSerialNumber = X509Helper(x509).getSerialNumber(issuerCert);
                bool issuerRevoked = crlLib.serialNumberIsRevoked(issuerSerialNumber, rootCrl);
                if (issuerRevoked) {
                    revert Issuer_Revoked(ca, issuerSerialNumber);
                }
            }

            bytes32 digest = sha256(pck.tbs);
            bool sigVerified = verifySignature(digest, pck.signature, issuerCert);
            if (!sigVerified) {
                revert Invalid_Signature();
            }
        } else {
            revert Missing_Issuer();
        }
    }

    function _validatePckTcb(bytes2 pceid, bytes18 tcbm, bytes memory der, uint256 pckExtensionPtr) internal view {
        (uint16 pcesvn, uint8[] memory cpusvns,, bytes memory pceidBytes) =
            pckLib.parsePckExtension(der, pckExtensionPtr);
        bool pceidMatched = bytes2(pceidBytes) == pceid;
        bytes memory encodedPceSvn = _littleEndianEncode(abi.encodePacked(pcesvn));
        bytes memory encodedCpuSvn;
        for (uint256 i = 0; i < cpusvns.length; i++) {
            encodedCpuSvn = abi.encodePacked(encodedCpuSvn, cpusvns[i]);
        }
        bytes memory encodedTcbmBytes = abi.encodePacked(encodedCpuSvn, encodedPceSvn);
        bool tcbIsValid = tcbm == bytes18(encodedTcbmBytes);
        if (!pceidMatched || !tcbIsValid) {
            revert TCB_Mismatch();
        }
    }

    function _littleEndianEncode(bytes memory input) internal pure returns (bytes memory encoded) {
        uint256 n = input.length;
        for (uint256 i = n; i > 0;) {
            encoded = abi.encodePacked(encoded, input[i - 1]);
            unchecked {
                i--;
            }
        }
    }

    /**
     * @notice converts the hexstring qeid and pceid inputs to bytes
     * @dev the length of every input is validated, so that a malformed input cannot be parsed
     * into a zero value and used to store or look up a collateral under an all-zero key
     */
    function _parseQeidAndPceid(string memory qeid, string memory pceid)
        internal
        pure
        returns (bytes16 qeidBytes, bytes2 pceidBytes)
    {
        require(bytes(qeid).length == 32, Invalid_Qeid_Length());
        require(bytes(pceid).length == 4, Invalid_Pceid_Length());
        qeidBytes = bytes16(uint128(_parseUintFromHex(qeid)));
        pceidBytes = bytes2(uint16(_parseUintFromHex(pceid)));
    }

    /**
     * @notice converts the hexstring platform SVN inputs to bytes
     * @dev the length of every input is validated, so that a malformed input cannot be parsed
     * into a zero value and used to store or look up a collateral under an all-zero key
     */
    function _parsePlatformSvns(string memory platformCpuSvn, string memory platformPceSvn)
        internal
        pure
        returns (bytes16 platformCpuSvnBytes, bytes2 platformPceSvnBytes)
    {
        require(bytes(platformCpuSvn).length == 32, Invalid_Platform_Cpu_Svn_Length());
        require(bytes(platformPceSvn).length == 4, Invalid_Platform_Pce_Svn_Length());
        platformCpuSvnBytes = bytes16(uint128(_parseUintFromHex(platformCpuSvn)));
        platformPceSvnBytes = bytes2(uint16(_parseUintFromHex(platformPceSvn)));
    }

    /**
     * @notice converts the hexstring tcbm input to bytes
     * @dev the length of the input is validated, so that a malformed input cannot be parsed into
     * a zero value and used to store or look up a collateral under an all-zero key
     */
    function _parseTcbm(string memory tcbm) internal pure returns (bytes18 tcbmBytes) {
        require(bytes(tcbm).length == 36, Invalid_Tcbm_Length());
        tcbmBytes = bytes18(uint144(_parseUintFromHex(tcbm)));
    }

    function _storePckValidity(bytes32 key, uint64 notValidBefore, uint64 notValidAfter) internal virtual;

    function _loadPckValidity(bytes32 key)
        internal
        view
        virtual
        returns (uint64 notValidBefore, uint64 notValidAfter);
}
