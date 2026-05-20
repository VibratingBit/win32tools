#include <win32tools/Tools/DriveInfo.hpp>

// winsock2 must precede windows.h / iphlpapi on MSVC.

#include <winsock2.h>

#include <winioctl.h>
#include <iphlpapi.h>


#include <algorithm>
#include <iomanip>
#include <sstream>
#include <cstring>

#pragma comment(lib, "iphlpapi.lib")

namespace w32t {

    // =============================================================================
    //  Constructor
    // =============================================================================

    DriveInfo::DriveInfo()
        : m_initialised{ false }
    {
    }

    // =============================================================================
    //  Public API
    // =============================================================================

    std::string DriveInfo::hddSerial()
    {
        if (!m_initialised) {
            m_initialised = initialise(); // This calls scanDrives once
        }

        if (m_currentRequestIndex >= m_allSerials.size()) {
            return m_allSerials[0];
        }

        return m_allSerials[m_currentRequestIndex++];
    }

    std::string DriveInfo::getMoboSerial() {
        DWORD size = GetSystemFirmwareTable('RSMB', 0, nullptr, 0);
        if (size == 0) return "";

        std::vector<BYTE> buffer(size);
        GetSystemFirmwareTable('RSMB', 0, buffer.data(), size);

        const BYTE *data = buffer.data();
        DWORD offset = 0;

        // SMBIOS structures follow a specific header format: [Type][Length][Handle]
        while (offset + 4 < size) {
            BYTE type = data[offset];
            BYTE length = data[offset + 1];

            // Type 2 is the "Baseboard Information" (Motherboard)
            if (type == 2) {
                // The Serial Number string index is usually at offset 0x07 in Type 2
                if (length > 0x07) {
                    BYTE serialIdx = data[offset + 0x07];

                    // Strings start after the formatted structure (offset + length)
                    const char *strPtr = reinterpret_cast<const char *>(&data[offset + length]);

                    // Iterate through null-terminated strings to find the one matching our index
                    for (BYTE i = 1; i <= 20; ++i) { // 20 is a safe upper bound
                        if (i == serialIdx) {
                            return trim(std::string(strPtr));
                        }
                        strPtr += strlen(strPtr) + 1;
                        if (*strPtr == '\0') break; // Double null means end of strings
                    }
                }
            }

            // Move to the next structure: skip the formatted part + the string section
            offset += length;
            while (offset < size - 1 && (data[offset] != 0 || data[offset + 1] != 0)) {
                offset++;
            }
            offset += 2; // Skip the double null terminator
        }

        return "UNKNOWN_MOBO";
    }

    std::string DriveInfo::generateMasterHWID() {
        // 1. Ensure we have data
        if (!m_initialised) initialise();

        // 2. Collect components
        std::string disk = (!m_allSerials.empty()) ? m_allSerials[0] : "DISK_NONE";
        std::string mac = macAddress();
        std::string mobo = getMoboSerial();

        // 3. Combine them
        // Interleaving them (your buildHwid method) or concatenating
        
        //std::string raw = disk + "-" + mobo + "-" + mac;

        // 4. Return the combined string
        return buildHwid(disk + mobo, mac);
    }

    std::string DriveInfo::macAddress()
    {
        if (!m_macAddress.empty())
            return m_macAddress;

        // GetAdaptersInfo needs a buffer; 16 adapters is more than enough.
        std::vector<IP_ADAPTER_INFO> adapters(16);
        ULONG bufLen = static_cast<ULONG>(adapters.size() * sizeof(IP_ADAPTER_INFO));

        DWORD rc = GetAdaptersInfo(adapters.data(), &bufLen);
        if (rc == ERROR_BUFFER_OVERFLOW) {
            // Resize to the required size and retry.
            adapters.resize(bufLen / sizeof(IP_ADAPTER_INFO) + 1);
            bufLen = static_cast<ULONG>(adapters.size() * sizeof(IP_ADAPTER_INFO));
            rc = GetAdaptersInfo(adapters.data(), &bufLen);
        }

        if (rc != ERROR_SUCCESS) {
            m_diag += "[MAC] GetAdaptersInfo failed, error=" + std::to_string(rc) + "\n";
            return {};
        }

        // Walk the linked list for the first Ethernet/WiFi adapter.
        const IP_ADAPTER_INFO *adapter = adapters.data();
        while (adapter) {
            if (adapter->AddressLength == 6) {
                std::ostringstream ss;
                ss << std::hex << std::uppercase << std::setfill('0');
                for (UINT i = 0; i < 6; ++i)
                    ss << std::setw(2) << static_cast<int>(adapter->Address[i]);
                m_macAddress = ss.str();
                return m_macAddress;
            }
            adapter = adapter->Next;
        }
        m_diag += "[MAC] No adapter with a 6-byte address found.\n";
        return {};
    }

    std::string DriveInfo::buildHwid(const std::string &first,
        const std::string &second)
    {
        std::string result;
        result.reserve(first.size() + second.size());
        std::size_t len = std::max(first.size(), second.size());
        for (std::size_t i = 0; i < len; ++i) {
            if (i < first.size())  result += first[i];
            if (i < second.size()) result += second[i];
        }
        return result;
    }



    std::vector<std::string> &DriveInfo::getSerials() {
        return m_allSerials;
    }

    // =============================================================================
    //  Private — initialise / scan
    // =============================================================================


    bool DriveInfo::initialise()
    {
        int found = scanDrives();
        if (found == 0)
            m_diag += "[HDD] No drives identified via SMART IOCTL.\n";
        return found > 0;
    }

    int DriveInfo::scanDrives()
    {
        int found = 0;
        m_allSerials.clear(); // Ensure you have a std::vector<std::string> m_allSerials in your class

        for (int driveIdx = 0; driveIdx < k_maxDrives; ++driveIdx) {
            std::string path = "\\\\.\\PhysicalDrive" + std::to_string(driveIdx);

            // We only need GENERIC_READ to query properties
            HANDLE hDrive = CreateFileA(path.c_str(), GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);

            if (hDrive == INVALID_HANDLE_VALUE) {
                DWORD err = GetLastError();
                if (err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND)
                    break;
                continue;
            }

            // Storage Query Property - Works for HDD, SSD, and NVMe
            STORAGE_PROPERTY_QUERY query{};
            query.PropertyId = StorageDeviceProperty;
            query.QueryType = PropertyStandardQuery;

            BYTE buffer[1024];
            DWORD bytesReturned = 0;

            if (DeviceIoControl(hDrive, IOCTL_STORAGE_QUERY_PROPERTY,
                &query, sizeof(query), &buffer, sizeof(buffer), &bytesReturned, nullptr))
            {
                auto *deviceDesc = reinterpret_cast<STORAGE_DEVICE_DESCRIPTOR *>(buffer);

                if (deviceDesc->SerialNumberOffset != 0 && deviceDesc->SerialNumberOffset != UINT32_MAX && deviceDesc->SerialNumberOffset < bytesReturned) {

                    const char *serialStart =
                        reinterpret_cast<const char *>(buffer + deviceDesc->SerialNumberOffset);

                    size_t maxLen = bytesReturned - deviceDesc->SerialNumberOffset;

                    // 1. Copy full bounded region
                    std::string serial(serialStart, maxLen);

                    // 2. Hard truncate at first '\0' if present
                    size_t nullPos = serial.find('\0');
                    if (nullPos != std::string::npos) {
                        serial.resize(nullPos);
                    }

                    // 3. Trim whitespace AND non-printable junk
                    auto is_bad = [](unsigned char c) {
                        return (c < 32 || c > 126); // keep printable ASCII only
                        };

                    serial.erase(
                        std::remove_if(serial.begin(), serial.end(), is_bad),
                        serial.end()
                    );


                    serial = trim(serial);

                    if (!serial.empty()) {
                        m_allSerials.push_back(serial);
                        // For backward compatibility with your existing m_hddSerial:
                        if (m_hddSerial.empty()) m_hddSerial = serial;
                        found++;
                    }
                }
            }
            CloseHandle(hDrive);
        }
        return found;
    }

    /*
    int DriveInfo::scanDrives()
    {
        int found = 0;

        for (int driveIdx = 0; driveIdx < k_maxDrives; ++driveIdx) {
            std::string path = "\\\\.\\PhysicalDrive" + std::to_string(driveIdx);

            // Need GENERIC_READ | GENERIC_WRITE for SMART IOCTLs.
            HANDLE hDrive = CreateFileA(
                path.c_str(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                nullptr,
                OPEN_EXISTING,
                0,
                nullptr);

            if (hDrive == INVALID_HANDLE_VALUE) {
                // Drive doesn't exist or no permission — stop scanning.
                DWORD err = GetLastError();
                if (err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND)
                    break;                          // No more drives.
                m_diag += "[HDD] Drive " + std::to_string(driveIdx)
                    + " open failed, error=" + std::to_string(err) + "\n";
                continue;
            }

            // ── Step 1: Query driver version to confirm SMART support ─────────
            DriveVersion ver{};
            DWORD returned = 0;

            BOOL versionOk = DeviceIoControl(
                hDrive,
                k_ioctlGetVersion,
                nullptr, 0,
                &ver, sizeof(ver),
                &returned, nullptr);

            if (!versionOk) {
                m_diag += "[HDD] Drive " + std::to_string(driveIdx)
                    + " SMART_GET_VERSION failed, error="
                    + std::to_string(GetLastError()) + "\n";
                CloseHandle(hDrive);
                continue;
            }

            if (ver.bIDEDeviceMap == 0) {
                m_diag += "[HDD] Drive " + std::to_string(driveIdx)
                    + " bIDEDeviceMap==0 (NVMe or unsupported device).\n";
                CloseHandle(hDrive);
                continue;
            }

            // ── Step 2: Send ATA / ATAPI IDENTIFY ────────────────────────────
            // Bit 4 in the device map indicates ATAPI for this slot.
            BYTE cmd = ((ver.bIDEDeviceMap >> driveIdx) & 0x10) ? k_cmdAtapi : k_cmdAta;

            std::memset(m_outBuf, 0, sizeof(m_outBuf));

            DWORD identifyReturned = 0;
            bool ok = sendIdentify(hDrive, cmd,
                static_cast<BYTE>(driveIdx),
                identifyReturned);

            if (ok) {
                // ── Step 3: Decode the 512-byte IDENTIFY sector ───────────────
                const auto *outPkt = reinterpret_cast<const DriveCmdOutput *>(m_outBuf);

                if (outPkt->DriverStatus.bDriverError != 0) {
                    m_diag += "[HDD] Drive " + std::to_string(driveIdx)
                        + " driver error=" + std::to_string(outPkt->DriverStatus.bDriverError)
                        + " IDE error=" + std::to_string(outPkt->DriverStatus.bIDEError)
                        + "\n";
                }
                else {
                    const auto *idSec =
                        reinterpret_cast<const IdSector *>(outPkt->bBuffer);
                    std::string serial = serialFromIdSector(*idSec);
                    if (!serial.empty()) {
                        m_hddSerial = serial;
                        ++found;
                        CloseHandle(hDrive);
                        break;   // First valid serial is enough.
                    }
                }
            }
            else {
                m_diag += "[HDD] Drive " + std::to_string(driveIdx)
                    + " SMART_RCV_DRIVE_DATA failed, error="
                    + std::to_string(GetLastError()) + "\n";
            }

            CloseHandle(hDrive);
        }
        return found;
    }*/

    // =============================================================================
    //  Private — IOCTL wrapper
    // =============================================================================

    bool DriveInfo::sendIdentify(HANDLE driveHandle,
        BYTE   command,
        BYTE   driveIndex,
        DWORD &bytesReturned)
    {
        // Build the input packet on the stack.
        DriveCmdInput input{};
        input.cBufferSize = k_idBufSize;
        input.irDriveRegs.bFeaturesReg = 0;
        input.irDriveRegs.bSectorCountReg = 1;
        input.irDriveRegs.bSectorNumberReg = 1;
        input.irDriveRegs.bCylLowReg = 0;
        input.irDriveRegs.bCylHighReg = 0;
        // Drive/Head register: 0xA0 selects LBA mode; bit 4 selects slave drive.
        input.irDriveRegs.bDriveHeadReg = static_cast<BYTE>(0xA0 | ((driveIndex & 1) << 4));
        input.irDriveRegs.bCommandReg = command;
        input.bDriveNumber = driveIndex;

        // The kernel reads exactly sizeof(DriveCmdInput)-1 bytes from the input
        // (the trailing flexible bBuffer[1] is not part of the IDENTIFY request).
        return DeviceIoControl(
            driveHandle,
            k_ioctlRecvDriveData,
            &input, static_cast<DWORD>(sizeof(DriveCmdInput) - 1),
            m_outBuf, static_cast<DWORD>(k_outBufBytes),
            &bytesReturned,
            nullptr) != FALSE;
    }

    // =============================================================================
    //  Private — serial extraction
    // =============================================================================

    std::string DriveInfo::serialFromIdSector(const IdSector &id)
    {
        // The ATA IDENTIFY serial number (words 10-19 = bytes 20-39) is stored
        // with each pair of bytes swapped relative to ASCII order.
        // e.g., the string "AB" is stored as bytes { 'B', 'A' }.
        char swapped[21]{};
        for (int i = 0; i < 20; i += 2) {
            swapped[i] = id.sSerialNumber[i + 1]; // high byte → first char
            swapped[i + 1] = id.sSerialNumber[i];     // low  byte → second char
        }
        swapped[20] = '\0';
        return trim(std::string(swapped));
    }

    std::string DriveInfo::trim(const std::string &s)
    {
        auto front = std::find_if(s.begin(), s.end(),
            [](unsigned char c) { return c > 0x20 && c < 0x7F; });
        auto back = std::find_if(s.rbegin(), s.rend(),
            [](unsigned char c) { return c > 0x20 && c < 0x7F; }).base();
        return (front < back) ? std::string(front, back) : std::string{};
    }

} // namespace w32t