#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <string>
#include <cstddef>
#include <vector>

namespace w32t {

    /// ATA task-file register set passed with SMART_RCV_DRIVE_DATA.
    struct DriveIdRegs {
        BYTE bFeaturesReg;      ///< Features / Error register.
        BYTE bSectorCountReg;   ///< Sector count (must be 1 for IDENTIFY).
        BYTE bSectorNumberReg;  ///< Sector number / LBA low (must be 1).
        BYTE bCylLowReg;        ///< Cylinder low / LBA mid  (0).
        BYTE bCylHighReg;       ///< Cylinder high / LBA high (0).
        BYTE bDriveHeadReg;     ///< 0xA0 | ((driveIndex & 1) << 4).
        BYTE bCommandReg;       ///< 0xEC = ATA IDENTIFY, 0xA1 = ATAPI IDENTIFY.
        BYTE bReserved;
    };

    /// Input packet for SMART_RCV_DRIVE_DATA (IOCTL code 0x0007C088).
    struct DriveCmdInput {
        ULONG       cBufferSize;   ///< Set to 512 for IDENTIFY.
        DriveIdRegs irDriveRegs;
        BYTE        bDriveNumber;  ///< 0-based physical drive index.
        BYTE        bReserved[3];
        ULONG       dwReserved[4];
        BYTE        bBuffer[1];
    };

    /// Error/status block returned inside every output packet.
    struct DriveDriverStatus {
        BYTE  bDriverError;
        BYTE  bIDEError;
        BYTE  bReserved[2];
        ULONG dwReserved[2];
    };

    /// Output packet for SMART_RCV_DRIVE_DATA — bBuffer contains the 512 bytes.
    struct DriveCmdOutput {
        ULONG             cBufferSize;
        DriveDriverStatus DriverStatus;
        BYTE              bBuffer[1]; ///< Actual data; caller allocates extra space.
    };

    /// Response to the SMART_GET_VERSION IOCTL (0x00074080).
    struct DriveVersion {
        BYTE  bVersion;
        BYTE  bRevision;
        BYTE  bReserved;
        BYTE  bIDEDeviceMap;  ///< Bit N set = IDE device N present.
        DWORD fCapabilities;
        DWORD dwReserved[4];
    };

    /// 512-byte ATA IDENTIFY DEVICE sector (words 0-255).
    struct IdSector {
        USHORT wGenConfig;
        USHORT wNumCyls;
        USHORT wReserved;
        USHORT wNumHeads;
        USHORT wBytesPerTrack;
        USHORT wBytesPerSector;
        USHORT wSectorsPerTrack;
        USHORT wVendorUnique[3];
        CHAR   sSerialNumber[20];      ///< Words 10-19: big-endian byte pairs.
        USHORT wBufferType;
        USHORT wBufferSize;
        USHORT wECCSize;
        CHAR   sFirmwareRev[8];
        CHAR   sModelNumber[40];
        USHORT wMoreVendorUnique;
        USHORT wDoubleWordIO;
        USHORT wCapabilities;
        USHORT wReserved1;
        USHORT wPIOTiming;
        USHORT wDMATiming;
        USHORT wBS;
        USHORT wNumCurrentCyls;
        USHORT wNumCurrentHeads;
        USHORT wNumCurrentSectorsPerTrack;
        ULONG  ulCurrentSectorCapacity;
        USHORT wMultSectorStuff;
        ULONG  ulTotalAddressableSectors;
        USHORT wSingleWordDMA;
        USHORT wMultiWordDMA;
        BYTE   bReserved[128];
    };

    // =============================================================================

    /// @brief Retrieves hardware identifiers: HDD serial number and MAC address.
    ///
    /// ### HDD serial
    /// Issues SMART_RCV_DRIVE_DATA (IOCTL 0x0007C088) via \\\\.\PhysicalDriveN.
    /// Requires:
    ///   - Administrator privileges (to open PhysicalDrive with GENERIC_READ | WRITE)
    ///   - An IDE/SATA drive whose driver exposes the SMART interface.
    ///   - NVMe drives typically require a separate NVMe pass-through IOCTL and
    ///     will return empty here.
    ///
    /// ### MAC address
    /// Uses GetAdaptersInfo — no elevated privilege required.
    ///
    /// Results are cached after the first successful call.
    class DriveInfo {
    public:
        DriveInfo();
        ~DriveInfo() = default;

        DriveInfo(const DriveInfo &) = delete;
        DriveInfo &operator=(const DriveInfo &) = delete;
        DriveInfo(DriveInfo &&) = default;
        DriveInfo &operator=(DriveInfo &&) = default;

        // ── Public API ───────────────────────────────────────────────────────────

        /// @return Trimmed HDD serial number, or empty string on failure.
        [[nodiscard]] std::string hddSerial();

        [[nodiscard]] std::string getMoboSerial();

        [[nodiscard]] std::string generateMasterHWID();

        /// @return Uppercase hex MAC "001A2B3C4D5E", or empty on failure.
        [[nodiscard]] std::string macAddress();

        [[nodiscard]] std::vector<std::string> &getSerials();

        /// @brief Interleave characters of @p first and @p second into one string.
        [[nodiscard]] static std::string buildHwid(const std::string &first,
            const std::string &second);

        /// @return Accumulated diagnostic log (empty if everything succeeded).
        [[nodiscard]] const std::string &diag() const noexcept { return m_diag; }

    private:
        // IOCTL codes — hardcoded, identical to what ntdddisk.h defines.
        static constexpr DWORD k_ioctlGetVersion = 0x00074080;
        static constexpr DWORD k_ioctlRecvDriveData = 0x0007C088;

        static constexpr int   k_maxDrives = 8;
        static constexpr DWORD k_idBufSize = 512;
        static constexpr BYTE  k_cmdAta = 0xEC;
        static constexpr BYTE  k_cmdAtapi = 0xA1;

        // Output buffer sized for the DriveCmdOutput header + 512 data bytes.
        // DriveCmdOutput::bBuffer[1] already covers the first byte, so we add 511.
        static constexpr std::size_t k_outBufBytes =
            sizeof(DriveCmdOutput) + k_idBufSize - 1;

        alignas(4) BYTE m_outBuf[k_outBufBytes]{};

        bool        m_initialised{ false };
        size_t      m_currentRequestIndex = 0;
        std::string m_hddSerial{};
        std::string m_macAddress{};
        std::string m_diag{};

        std::vector<std::string> m_allSerials{};

        // ── Internals ────────────────────────────────────────────────────────────

        bool initialise();
        int  scanDrives();

        /// Open PhysicalDriveN, send ATA IDENTIFY, fill m_outBuf.
        bool sendIdentify(HANDLE driveHandle,
            BYTE   command,
            BYTE   driveIndex,
            DWORD &bytesReturned);

        /// Pull the 20-byte serial field out of an IdSector and byte-swap it.
        static std::string serialFromIdSector(const IdSector &id);

        /// Remove leading/trailing spaces and non-printable characters.
        static std::string trim(const std::string &s);
    };

} // namespace w32t