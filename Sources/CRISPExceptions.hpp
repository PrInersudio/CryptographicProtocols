#ifndef CRISP_EXCEPTIONS
#define CRISP_EXCEPTIONS

#include <exception>
#include <string>

namespace crispex {
    class CRISPException : public std::exception {
    private:
        std::string message_;
    public:
        explicit CRISPException(const std::string& msg) : message_(msg) {}
        const char* what() const noexcept override { return message_.c_str(); }
        virtual ~CRISPException() noexcept = default;
    };

    class privilege_error : public CRISPException {
    public:
        using CRISPException::CRISPException; 
    };

    class file_format_error : public CRISPException {
    public:
        using CRISPException::CRISPException; 
    };

    class invalid_argument : public CRISPException {
    public:
        using CRISPException::CRISPException; 
    };

    class help_param : public CRISPException {
    public:
        using CRISPException::CRISPException; 
    };

    class compromise_attempt : public CRISPException {
    public:
        using CRISPException::CRISPException; 
    };

    class CRISPNetworkErrors : public CRISPException {
    public:
        using CRISPException::CRISPException;
        virtual ~CRISPNetworkErrors() noexcept = default;
    };

    class init_connection_error : public CRISPNetworkErrors {
    public:
        using CRISPNetworkErrors::CRISPNetworkErrors; 
    };

    class socket_closed : public CRISPNetworkErrors {
    public:
        using CRISPNetworkErrors::CRISPNetworkErrors; 
    };

    class recv_error : public CRISPNetworkErrors {
    public:
        using CRISPNetworkErrors::CRISPNetworkErrors; 
    };

    class send_error : public CRISPNetworkErrors {
    public:
        using CRISPNetworkErrors::CRISPNetworkErrors; 
    };

    class CRISPCryptoErrors : public CRISPException {
    public:
        using CRISPException::CRISPException;
        virtual ~CRISPCryptoErrors() noexcept = default;
    };

    class rbg_reseed_await : public CRISPCryptoErrors {
    public:
        using CRISPCryptoErrors::CRISPCryptoErrors; 
    };

    class lack_of_entropy : public CRISPCryptoErrors {
    public:
        using CRISPCryptoErrors::CRISPCryptoErrors; 
    };

    class rbg_query_limit : public CRISPCryptoErrors {
    public:
        using CRISPCryptoErrors::CRISPCryptoErrors; 
    };
}

#endif