#ifndef PROCESS_GUARD_PGS_SERVICE_HELPERS_H
#define PROCESS_GUARD_PGS_SERVICE_HELPERS_H

#include "Process_Guard/PGUtil.h"

#include <filesystem>
#include <fstream>
#include <cctype>
#include <cstdint>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

namespace ProcessGuard::service_util
{
    inline std::string jsonEscape(const std::string &value)
    {
        std::ostringstream out;
        for (unsigned char ch : value)
        {
            switch (ch)
            {
            case '\\': out << "\\\\"; break;
            case '"': out << "\\\""; break;
            case '\b': out << "\\b"; break;
            case '\f': out << "\\f"; break;
            case '\n': out << "\\n"; break;
            case '\r': out << "\\r"; break;
            case '\t': out << "\\t"; break;
            default:
                if (ch < 0x20)
                {
                    out << "\\u" << std::hex << std::setw(4) << std::setfill('0') << static_cast<int>(ch)
                        << std::dec << std::setfill(' ');
                }
                else
                {
                    out << static_cast<char>(ch);
                }
                break;
            }
        }
        return out.str();
    }

    inline std::string jsonStringValue(const std::string &text, const std::string &key)
    {
        const std::string needle = "\"" + key + "\"";
        std::size_t pos = text.find(needle);
        if (pos == std::string::npos) return std::string();
        pos = text.find(':', pos + needle.size());
        if (pos == std::string::npos) return std::string();
        ++pos;
        while (pos < text.size() && std::isspace(static_cast<unsigned char>(text[pos]))) ++pos;
        if (pos >= text.size() || text[pos] != '"') return std::string();
        ++pos;
        std::string out;
        bool escaped = false;
        for (; pos < text.size(); ++pos)
        {
            const char ch = text[pos];
            if (escaped)
            {
                switch (ch)
                {
                case '"': out.push_back('"'); break;
                case '\\': out.push_back('\\'); break;
                case 'n': out.push_back('\n'); break;
                case 'r': out.push_back('\r'); break;
                case 't': out.push_back('\t'); break;
                default: out.push_back(ch); break;
                }
                escaped = false;
                continue;
            }
            if (ch == '\\') { escaped = true; continue; }
            if (ch == '"') break;
            out.push_back(ch);
        }
        return out;
    }

    inline std::string jsonNumberText(const std::string &text, const std::string &key)
    {
        const std::string needle = "\"" + key + "\"";
        std::size_t pos = text.find(needle);
        if (pos == std::string::npos) return std::string();
        pos = text.find(':', pos + needle.size());
        if (pos == std::string::npos) return std::string();
        ++pos;
        while (pos < text.size() && std::isspace(static_cast<unsigned char>(text[pos]))) ++pos;
        const std::size_t start = pos;
        if (pos < text.size() && text[pos] == '-') ++pos;
        while (pos < text.size() && std::isdigit(static_cast<unsigned char>(text[pos]))) ++pos;
        return pos > start ? text.substr(start, pos - start) : std::string();
    }

    inline std::string jsonRawValue(const std::string &text, const std::string &key)
    {
        const std::string needle = "\"" + key + "\"";
        std::size_t pos = text.find(needle);
        if (pos == std::string::npos) return std::string();
        pos = text.find(':', pos + needle.size());
        if (pos == std::string::npos) return std::string();
        ++pos;
        while (pos < text.size() && std::isspace(static_cast<unsigned char>(text[pos]))) ++pos;
        if (pos >= text.size()) return std::string();
        const char open = text[pos];
        if (open == '{' || open == '[')
        {
            const char close = open == '{' ? '}' : ']';
            int depth = 0;
            bool inString = false;
            bool escaped = false;
            for (std::size_t i = pos; i < text.size(); ++i)
            {
                const char ch = text[i];
                if (inString)
                {
                    if (escaped) { escaped = false; continue; }
                    if (ch == '\\') { escaped = true; continue; }
                    if (ch == '"') inString = false;
                    continue;
                }
                if (ch == '"') { inString = true; continue; }
                if (ch == open) ++depth;
                else if (ch == close)
                {
                    --depth;
                    if (depth == 0) return text.substr(pos, i - pos + 1);
                }
            }
            return std::string();
        }
        if (open == '"')
        {
            bool escaped = false;
            for (std::size_t i = pos + 1; i < text.size(); ++i)
            {
                if (escaped) { escaped = false; continue; }
                if (text[i] == '\\') { escaped = true; continue; }
                if (text[i] == '"') return text.substr(pos, i - pos + 1);
            }
            return std::string();
        }
        std::size_t end = pos;
        while (end < text.size() && text[end] != ',' && text[end] != '}' && text[end] != ']') ++end;
        return util::trim(text.substr(pos, end - pos));
    }

    inline std::vector<std::string> jsonStringArray(const std::string &text, const std::string &key)
    {
        std::vector<std::string> out;
        const std::string raw = jsonRawValue(text, key);
        if (raw.size() < 2 || raw.front() != '[') return out;
        std::size_t pos = 1;
        while (pos < raw.size())
        {
            while (pos < raw.size() && (std::isspace(static_cast<unsigned char>(raw[pos])) || raw[pos] == ',')) ++pos;
            if (pos >= raw.size() || raw[pos] != '"') break;
            ++pos;
            std::string value;
            bool escaped = false;
            for (; pos < raw.size(); ++pos)
            {
                const char ch = raw[pos];
                if (escaped)
                {
                    switch (ch)
                    {
                    case '"': value.push_back('"'); break;
                    case '\\': value.push_back('\\'); break;
                    case 'n': value.push_back('\n'); break;
                    case 'r': value.push_back('\r'); break;
                    case 't': value.push_back('\t'); break;
                    default: value.push_back(ch); break;
                    }
                    escaped = false;
                    continue;
                }
                if (ch == '\\') { escaped = true; continue; }
                if (ch == '"') { ++pos; out.push_back(value); break; }
                value.push_back(ch);
            }
        }
        return out;
    }

    inline std::int64_t jsonInt64(const std::string &text, const std::string &key, std::int64_t fallback)
    {
        const std::string value = jsonNumberText(text, key);
        if (value.empty()) return fallback;
        try { return std::stoll(value); } catch (const std::exception &) { return fallback; }
    }

    inline bool isOpaqueId(const std::string &id, const std::string &prefix)
    {
        if (id.size() != prefix.size() + 32 || id.rfind(prefix, 0) != 0) return false;
        for (std::size_t i = prefix.size(); i < id.size(); ++i)
        {
            if (!std::isxdigit(static_cast<unsigned char>(id[i]))) return false;
        }
        return true;
    }

    inline bool looksLikeJsonObjectOrArray(const std::string &text)
    {
        const std::string t = util::trim(text);
        return !t.empty() && ((t.front() == '{' && t.back() == '}') || (t.front() == '[' && t.back() == ']'));
    }

    inline std::string jsonRpcError(const std::string &id, const std::string &code, const std::string &message)
    {
        const std::string idJson = id.empty() ? std::string("null") : ("\"" + jsonEscape(id) + "\"");
        return "{\"jsonrpc\":\"2.0\",\"id\":" + idJson +
               ",\"error\":{\"code\":\"" + jsonEscape(code) +
               "\",\"message\":\"" + jsonEscape(message) + "\"}}";
    }

    inline std::string jsonRpcResult(const std::string &id, const std::string &resultJson)
    {
        const std::string idJson = id.empty() ? std::string("null") : ("\"" + jsonEscape(id) + "\"");
        return "{\"jsonrpc\":\"2.0\",\"id\":" + idJson + ",\"result\":" + resultJson + "}";
    }

    inline std::filesystem::path moduleStagingRootForModulesDir(const std::string &modulesDir)
    {
        std::filesystem::path root = std::filesystem::path(util::utf8ToWide(modulesDir)).parent_path();
        if (root.empty())
        {
            root = L".";
        }
        return root / L"modules_staging";
    }

    inline bool pathHasExtension(const std::filesystem::path &path, const std::string &extension)
    {
        return util::toLowerAscii(util::wideToUtf8(path.extension().wstring())) == extension;
    }

    inline bool readTextFileLimited(const std::filesystem::path &path,
                                    std::string &out,
                                    std::size_t limitBytes = 1024 * 1024)
    {
        out.clear();
        std::error_code ec;
        if (!std::filesystem::is_regular_file(path, ec))
        {
            return false;
        }
        const auto size = std::filesystem::file_size(path, ec);
        if (ec || size > limitBytes)
        {
            return false;
        }
        std::ifstream in(path, std::ios::in | std::ios::binary);
        if (!in.is_open())
        {
            return false;
        }
        std::ostringstream oss;
        oss << in.rdbuf();
        out = oss.str();
        return true;
    }

    inline bool readWholeFile(const std::filesystem::path &path, std::string &out)
    {
        std::ifstream in(path, std::ios::in | std::ios::binary);
        if (!in.is_open())
        {
            return false;
        }
        std::ostringstream oss;
        oss << in.rdbuf();
        out = oss.str();
        return true;
    }

    inline bool writeWholeFile(const std::filesystem::path &path, const std::string &data)
    {
        std::ofstream out(path, std::ios::out | std::ios::binary | std::ios::trunc);
        if (!out.is_open())
        {
            return false;
        }
        out.write(data.data(), static_cast<std::streamsize>(data.size()));
        out.flush();
        return out.good();
    }
}

#endif // PROCESS_GUARD_PGS_SERVICE_HELPERS_H
