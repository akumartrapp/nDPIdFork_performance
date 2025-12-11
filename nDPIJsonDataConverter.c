#include "nDPIJsonDataConverter.h"
#include "ndpi_typedefs.h"
#include "../json-c/include/json-c/json.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TRUE 1
#define FALSE 0
#define BOOL int
#define RANDOM_UNINITIALIZED_NUMBER_VALUE 0xFFFFFFFF // UINT_MAX (4294967295)
#define RANDOM_UNINITIALIZED_INT_VALUE -84742891
#define INVALID_TIMESTAMP UINT64_MAX


static bool matchEntryInParamsVector(const char * srcIP, const char * destIP, int destPort);

    // Array to store SkipParameters
struct SkipParameters * paramsVector = NULL;
int vectorSize = 0;
static bool hasAlreadyReadLogFile = false;

// Define a structure to represent skipParameters
struct SkipParameters
{
    char * sourceIP;
    char * destinationIP;
    int destinationPort; // Use -1 if not present
};

// Define the structure for ndpiData
struct NDPI_Risk
{
    int key;
    char* risk;
    char* severity;
    struct {
        int total;
        int client;
        int server;
    } risk_score;
};

struct NDPI_Confidence
{
    int key;
    char* value;
};

struct NDPI_http
{
    char * request_content_type;
    char* content_type;
    char* user_agent;
    char* filename;
    unsigned int code;
};

struct NDPI_tls
{
    char* version;
    char* server_names;
    char* ja4;
    char* ja3s;
    char* cipher;
    char* issuerDN;
    char* subjectDN;
};

struct Xfer_Packets
{
    unsigned int packets;
    unsigned int bytes;
};

struct Root_xfer
{
    struct Xfer_Packets source;
    struct Xfer_Packets destination;
    int flow_src_tot_l4_payload_len;
    int flow_dst_tot_l4_payload_len;
};

struct Root_data
{
    char* src_ip;
    int src_port;
    unsigned int src_packets;
    unsigned int src_bytes;
    int flow_src_tot_l4_payload_len;
    char* dest_ip;
    int dst_port;
    unsigned int des_packets;
    unsigned int des_bytes;
    int flow_dst_tot_l4_payload_len;
    char* l3_proto;
    char* l4_proto;
    int ip;
    char* proto;
    char* breed;
    int flow_id;
    unsigned int flow_event_id;
    unsigned int packet_id;
    char* event_start;
    char* event_end;
    uint64_t event_duration;
    struct Root_xfer xfer;
    char* hostname;
};

struct NDPI_Data
{
    struct NDPI_Risk* flow_risk;
    size_t flow_risk_count;
    struct NDPI_Confidence confidence;
    char* confidence_value;
    struct NDPI_tls tls;
    char* proto_id;
    char * protocol;
    char* proto_by_ip;
    int proto_by_ip_id;
    int encrypted;
    int category_id;
    char* category;
    struct NDPI_http http;
};

static char * strDuplicate(const char * inputSting)
{
#ifdef _WIN32
    // Windows-specific code
    return _strdup(inputSting);
#else
    // Non-Windows (assume POSIX) code
    return strdup(inputSting);
#endif
}

void convert_usec_to_utc_string(uint64_t usec_since_epoch, char * output, size_t output_len)
{
    time_t seconds = usec_since_epoch / 1000000;

    struct tm gmtime_result;
    gmtime_r(&seconds, &gmtime_result);

    // Format: 2025-07-11T01:08:20Z
    snprintf(output,
             output_len,
             "%04d-%02d-%02dT%02d:%02d:%02dZ",
             gmtime_result.tm_year + 1900,
             gmtime_result.tm_mon + 1,
             gmtime_result.tm_mday,
             gmtime_result.tm_hour,
             gmtime_result.tm_min,
             gmtime_result.tm_sec);
}

static inline uint64_t max_u64(uint64_t a, uint64_t b)
{
    return (a > b) ? a : b;
}

static inline uint64_t convert_usec_to_nsec(uint64_t usec)
{
    return usec * 1000;
}

static const char* ndpi_risk2description(ndpi_risk_enum risk)
{

    switch (risk) {
    case NDPI_URL_POSSIBLE_XSS:
        return("HTTP only: this risk indicates a possible `XSS (Cross Side Scripting) <https://en.wikipedia.org/wiki/Cross-site_scripting>`_ attack.");

    case NDPI_URL_POSSIBLE_SQL_INJECTION:
        return("HTTP only: this risk indicates a possible `SQL Injection attack <https://en.wikipedia.org/wiki/SQL_injection>`_.");

    case NDPI_URL_POSSIBLE_RCE_INJECTION:
        return("HTTP only: this risk indicates a possible `RCE (Remote Code Execution) attack <https://en.wikipedia.org/wiki/Arbitrary_code_execution>`_.");

    case NDPI_BINARY_APPLICATION_TRANSFER:
        return("HTTP only: this risk indicates that a binary application is downloaded/uploaded. Detected applications include Windows binaries, Linux executables, Unix scripts and Android apps.");

    case NDPI_KNOWN_PROTOCOL_ON_NON_STANDARD_PORT:
        return("This risk indicates a known protocol used on a non standard port. Example HTTP is supposed to use TCP/80, and in case it is detected on TCP/1234 this risk is detected.");

    case NDPI_TLS_SELFSIGNED_CERTIFICATE:
        return("TLS/QUIC only: this risk is triggered when a `self-signed certificate <https://en.wikipedia.org/wiki/Self-signed_certificate>`_ is used.");

    case NDPI_TLS_OBSOLETE_VERSION:
        return("Risk triggered when TLS version is older than 1.1.");

    case NDPI_TLS_WEAK_CIPHER:
        return("Risk triggered when an unsafe TLS cipher is used. See `this page <https://community.qualys.com/thread/18212-how-does-qualys-determine-the-server-cipher-suites>`_ for a list of insecure ciphers.");

    case NDPI_TLS_CERTIFICATE_EXPIRED:
        return("Risk triggered when a TLS certificate is expired, i.e. the current date falls outside of the certificate validity dates.");

    case NDPI_TLS_CERTIFICATE_MISMATCH:
        return("Risk triggered when a TLS certificate does not match the hostname we're accessing. Example you do http://www.aaa.com and the TLS certificate returned is for www.bbb.com.");

    case NDPI_HTTP_SUSPICIOUS_USER_AGENT:
        return("HTTP only: this risk is triggered whenever the user agent contains suspicious characters or its format is suspicious. Example: <?php something ?> is a typical suspicious user agent.");

    case NDPI_NUMERIC_IP_HOST:
        return("This risk is triggered whenever a HTTP/TLS/QUIC connection is using a literal IPv4 or IPv6 address as ServerName (TLS/QUIC; example: SNI=1.2.3.4) or as Hostname (HTTP; example: http://1.2.3.4.).");

    case NDPI_HTTP_SUSPICIOUS_URL:
        return("HTTP only: this risk is triggered whenever the accessed URL is suspicious. Example: http://127.0.0.1/msadc/..%255c../..%255c../..%255c../winnt/system32/cmd.exe.");

    case NDPI_HTTP_SUSPICIOUS_HEADER:
        return("HTTP only: this risk is triggered whenever the HTTP peader contains suspicious entries such as Uuid, TLS_version, Osname that are unexpected on the HTTP header.");

    case NDPI_TLS_NOT_CARRYING_HTTPS:
        return("TLS only: this risk indicates that this TLS flow will not be used to transport HTTP content. Example VPNs use TLS to encrypt data rather to carry HTTP. This is useful to spot this type of cases.");

    case NDPI_SUSPICIOUS_DGA_DOMAIN:
        return("A `DGA <https://en.wikipedia.org/wiki/Domain_generation_algorithm>`_ is used to generate domain names often used by malwares. This risk indicates that this domain name can (but it's not 100% sure) a DGA as its name is suspicious.");

    case NDPI_MALFORMED_PACKET:
        return("This risk is generated when a packet (e.g. a DNS packet) has an unexpected formt. This can indicate a protocol error or more often an attempt to jeopardize a valid protocol to carry other type of data.");

    case NDPI_SSH_OBSOLETE_CLIENT_VERSION_OR_CIPHER:
        return("This risk is generated whenever a SSH client uses an obsolete SSH protocol version or insecure ciphers.");

    case NDPI_SSH_OBSOLETE_SERVER_VERSION_OR_CIPHER:
        return("This risk is generated whenever a SSH server uses an obsolete SSH protocol version or insecure ciphers.");

    case NDPI_SMB_INSECURE_VERSION:
        return("This risk indicates that the `SMB <https://en.wikipedia.org/wiki/Server_Message_Block>`_ version used is insecure (i.e. v1).");

    /*case NDPI_TLS_SUSPICIOUS_ESNI_USAGE:
        return("`SNI <https://en.wikipedia.org/wiki/Server_Name_Indication>`_ is a way to carry in TLS the host/domain name we're accessing. ESNI means encrypted SNI and it is a way to mask SNI (carried in clear text in the TLS header) with encryption. While this practice is legal, it could be used for hiding data or for attacks such as a suspicious `domain fronting <https://github.com/SixGenInc/Noctilucent/blob/master/docs/>`_.");*/

    case NDPI_UNSAFE_PROTOCOL:
        return("This risk indicates that the protocol used is insecure and that a secure protocol should be used (e.g. Telnet vs SSH).");

    case NDPI_DNS_SUSPICIOUS_TRAFFIC:
        return("This risk is returned when DNS traffic returns an unexpected/obsolete `record type <https://en.wikipedia.org/wiki/List_of_DNS_record_types>`_."); /* Exfiltration ? */

    case NDPI_TLS_MISSING_SNI:
        return("TLS needs to carry the the `SNI <https://en.wikipedia.org/wiki/Server_Name_Indication>`_ of the remote server we're accessing. Unfortunately SNI is optional in TLS so it can be omitted. In this case this risk is triggered as this is a non-standard situation that indicates a potential security problem or a protocol using TLS for other purposes (or a protocol bug).");

    case NDPI_HTTP_SUSPICIOUS_CONTENT:
        return("HTTP only: risk reported when HTTP carries content in expected format. Example the HTTP header indicates that the context is text/html but the real content is not readeable (i.e. it can transport binary data). In general this is an attempt to use a valid MIME type to carry data that does not match the type.");

    case NDPI_RISKY_ASN:
        return("This is a placeholder for traffic exchanged with `ASN <https://en.wikipedia.org/wiki/Autonomous_system_(Internet)>`_ that are considered risky. nDPI does not fill this risk that instead should be filled by aplications sitting on top of nDPI (e.g. ntopng).");

    case NDPI_RISKY_DOMAIN:
        return("This is a placeholder for traffic exchanged with domain names that are considered risky. nDPI does not fill this risk that instead should be filled by aplications sitting on top of nDPI (e.g. ntopng).");

   /* case NDPI_MALICIOUS_JA3:
        return("`JA3 <https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s-247362855967>`_ is a method to fingerprint TLS traffic. This risk indicates that the JA3 of the TLS connection is considered suspicious (i.e. it has been found in known malware JA3 blacklists). nDPI does not fill this risk that instead should be filled by aplications sitting on top of nDPI (e.g. ntopng).");*/

    case NDPI_MALICIOUS_SHA1_CERTIFICATE:
        return("TLS certificates are uniquely identified with a `SHA1 <https://en.wikipedia.org/wiki/SHA-1>`_ hash value. If such hash is found on a blacklist, this risk can be used. As for other risks, this is a placeholder as nDPI does not fill this risk that instead should be filled by aplications sitting on top of nDPI (e.g. ntopng).");

    case NDPI_DESKTOP_OR_FILE_SHARING_SESSION:
        return("This risk is set when the flow carries desktop or file sharing sessions (e.g. TeamViewer or AnyDesk just to mention two).");

    case NDPI_TLS_UNCOMMON_ALPN:
        return("This risk is set when the `ALPN <https://en.wikipedia.org/wiki/Application-Layer_Protocol_Negotiation>`_ (it indicates the protocol carried into this TLS flow, for instance HTTP/1.1) is uncommon with respect to the list of expected values");

    case NDPI_TLS_CERT_VALIDITY_TOO_LONG:
        return("From 01/09/2020 TLS certificates lifespan is limited to `13 months <https://www.appviewx.com/blogs/tls-certificate-lifespans-now-capped-at-13-months/>`_. This risk is triggered for certificates not respecting this directive.");

    case NDPI_TLS_SUSPICIOUS_EXTENSION:
        return("This risk is triggered when the domain name (SNI extension) is not printable and thus it is a problem. In TLS extensions can be dynamically specified by the client in the hello packet.");

    case NDPI_TLS_FATAL_ALERT:
        return("This risk is triggered when a TLS fatal alert is detected in the TLS flow. See `this page <https://techcommunity.microsoft.com/t5/iis-support-blog/ssl-tls-alert-protocol-and-the-alert-codes/ba-p/377132>`_ for details.");

    case NDPI_SUSPICIOUS_ENTROPY:
        return("This risk is used to detect suspicious data carried in ICMP packets whose entropy (used to measure how data is distributed, hence to indirectly guess the type of data carried on) is suspicious and thus that it can indicate a data leak. Suspicious values indicate random entropy or entropy that is similar to encrypted traffic. In the latter case, this can be a suspicious data exfiltration symptom.");

    case NDPI_CLEAR_TEXT_CREDENTIALS:
        return("Clear text protocols are not bad per-se, but they should be avoided when they carry credentials as they can be intercepted by malicious users. This risk is triggered whenever clear text protocols (e.g. FTP, HTTP, IMAP...) contain credentials in clear text (read it as nDPI does not trigger this risk for HTTP connections that do not carry credentials).");

    case NDPI_DNS_LARGE_PACKET:
        return("`DNS <https://en.wikipedia.org/wiki/Domain_Name_System>`_ packets over UDP should be limited to 512 bytes. DNS packets over this threshold indicate a potential security risk (e.g. use DNS to carry data) or a misconfiguration.");

    case NDPI_DNS_FRAGMENTED:
        return("UDP `DNS <https://en.wikipedia.org/wiki/Domain_Name_System>`_ packets cannot be fragmented. If so, this indicates a potential security risk (e.g. use DNS to carry data) or a misconfiguration.");

    case NDPI_INVALID_CHARACTERS:
        return("The risk is set whenever a dissected protocol contains characters not allowed in that protocol field. For example a DNS hostname must only contain a subset of all printable characters or else this risk is set. Additionally, some TLS protocol fields are checked for printable characters as well.");

    case NDPI_POSSIBLE_EXPLOIT:
        return("The risk is set whenever a possible exploit (e.g. `Log4J/Log4Shell <https://en.wikipedia.org/wiki/Log4Shell>`_) is detected.");

    case NDPI_TLS_CERTIFICATE_ABOUT_TO_EXPIRE:
        return("The risk is set whenever a TLS certificate is close to the expiration date.");

    case NDPI_PUNYCODE_IDN:
        return("The risk is set whenever a domain name is specified in IDN format as they are sometimes used in `IDN homograph attacks <https://en.wikipedia.org/wiki/IDN_homograph_attack>`_.");

    case NDPI_ERROR_CODE_DETECTED:
        return("The risk is set whenever an error code is detected in the underlying protocol (e.g. HTTP and DNS).");

    case NDPI_HTTP_CRAWLER_BOT:
        return("The risk is set whenever a crawler/bot/robot has been detected");

    case NDPI_ANONYMOUS_SUBSCRIBER:
        return("The risk is set whenever the (source) ip address has been anonymized and it can't be used to identify the subscriber. Example: the flow is generated by an iCloud - private - relay exit node.");

    case NDPI_UNIDIRECTIONAL_TRAFFIC:
        return("The risk is set whenever the flow has unidirectional traffic (typically no traffic on the server to client direction). This risk is not triggered for multicast / broadcast destinations.");

    case NDPI_HTTP_OBSOLETE_SERVER:
        return("This risk is generated whenever a HTTP server uses an obsolete HTTP server version.");

    case NDPI_PERIODIC_FLOW:
        return("This risk is generated whenever a flow is observed at a specific periodic pace (e.g. every 10 seconds).");

    case NDPI_MINOR_ISSUES:
        return("Minor packet/flow issues (e.g. DNS traffic with zero TTL) have been detected.");

    case NDPI_TCP_ISSUES:
        return("Relevant TCP connection issues such as connection refused, scan, or probe attempt.");

    default:

        return("ERROR: Unknown Risk");
    }
}


/*--------------------------------------------------------------------------------------------------------------------------------------------------------*/

// Function to convert ndpi field to the desired structure
struct NDPI_Data getnDPIStructure(const char * ndpiJson, const char * const json_string_with_http_or_tls_info )
{
    struct NDPI_Data result;
    result.flow_risk = NULL;
    result.flow_risk_count = 0;
    result.confidence.key = RANDOM_UNINITIALIZED_NUMBER_VALUE;
    result.confidence.value = NULL;
    result.tls.version = NULL;
    result.tls.server_names = NULL;
    result.tls.ja4 = NULL;
    result.tls.ja3s = NULL;
    result.tls.cipher = NULL;
    result.tls.issuerDN = NULL;
    result.tls.subjectDN = NULL;

    result.confidence_value = NULL;
    result.proto_id = NULL;
    result.protocol = NULL;
    result.proto_by_ip = NULL;
    result.proto_by_ip_id = RANDOM_UNINITIALIZED_INT_VALUE;
    result.encrypted = RANDOM_UNINITIALIZED_INT_VALUE;
    result.category_id = RANDOM_UNINITIALIZED_INT_VALUE;
    result.category = NULL;
    result.http.request_content_type = NULL;
    result.http.content_type = NULL;
    result.http.user_agent = NULL;
    result.http.filename = NULL;
    result.http.code = RANDOM_UNINITIALIZED_NUMBER_VALUE;

    // Parse JSON string
    json_object* root = json_tokener_parse(ndpiJson);
    if (root == NULL)
    {
        fprintf(stderr, "Error parsing JSON\n");
        return result;
    }

    json_object* ndpiObject;
    if (json_object_object_get_ex(root, "ndpi", &ndpiObject))
    {
        // Extract flow_risk array
        json_object* flowRiskObj = NULL;
        if (json_object_object_get_ex(ndpiObject, "flow_risk", &flowRiskObj) && json_object_is_type(flowRiskObj, json_type_object))
        {
            // Get the number of elements in the flow_risk object
            int flowRiskCount = json_object_object_length(flowRiskObj);

            // Allocate memory for NDPI_Risk array
            result.flow_risk = malloc(flowRiskCount * sizeof(struct NDPI_Risk));
            if (result.flow_risk == NULL) 
            {
                fprintf(stderr, "Memory allocation failed\n");
                return result;
            }

            // Initialize the count of flow_risk elements
            result.flow_risk_count = 0;

            // Iterate through each element of the flow_risk object
            json_object_object_foreach(flowRiskObj, key, val) 
            {
                json_object* riskObj = val;

                // Extract risk, severity, and risk_score objects
                json_object* risk;
                json_object* severity;
                json_object* riskScoreObj;
                if (json_object_object_get_ex(riskObj, "risk", &risk) &&
                    json_object_object_get_ex(riskObj, "severity", &severity) &&
                    json_object_object_get_ex(riskObj, "risk_score", &riskScoreObj))
                {

                    // Extract risk_score values
                    json_object* totalObj;
                    json_object* clientObj;
                    json_object* serverObj;
                    if (json_object_object_get_ex(riskScoreObj, "total", &totalObj) &&
                        json_object_object_get_ex(riskScoreObj, "client", &clientObj) &&
                        json_object_object_get_ex(riskScoreObj, "server", &serverObj))
                    {

                        // Allocate memory for the NDPI_Risk structure
                        result.flow_risk[result.flow_risk_count].risk = strDuplicate(json_object_get_string(risk));
                        result.flow_risk[result.flow_risk_count].severity = strDuplicate(json_object_get_string(severity));
                        result.flow_risk[result.flow_risk_count].risk_score.total = json_object_get_int(totalObj);
                        result.flow_risk[result.flow_risk_count].risk_score.client = json_object_get_int(clientObj);
                        result.flow_risk[result.flow_risk_count].risk_score.server = json_object_get_int(serverObj);
                        result.flow_risk[result.flow_risk_count].key = atoi(key);

                        // Increment the count of flow_risk elements
                        result.flow_risk_count++;
                    }
                }
            }
        }

        // Extract confidence object
        json_object* confidenceObj;
        if (json_object_object_get_ex(ndpiObject, "confidence", &confidenceObj) && json_object_is_type(confidenceObj, json_type_object))
        {
            // Extract key and value
            const char* keyStr = NULL;
            json_object_object_foreach(confidenceObj, key, val) 
            {
                keyStr = key;
                break; // Assuming there's only one key in confidence
            }
            json_object* value = json_object_object_get(confidenceObj, keyStr);

            // Store confidence data in the result
            result.confidence.key = atoi(keyStr);
            result.confidence.value = strDuplicate(json_object_get_string(value));
        }

        // Extract rest of ndpi data
        json_object* proto_id;
        if (json_object_object_get_ex(ndpiObject, "proto_id", &proto_id))
        {
            result.proto_id = strDuplicate(json_object_get_string(proto_id));
        }
       
        json_object* proto_by_ip;
        if (json_object_object_get_ex(ndpiObject, "proto_by_ip", &proto_by_ip))
        {
            result.proto_by_ip = strDuplicate(json_object_get_string(proto_by_ip));
        }

        json_object * protocol;
        if (json_object_object_get_ex(ndpiObject, "proto", &protocol))
        {
            result.protocol = strDuplicate(json_object_get_string(protocol));
        }

        json_object* proto_by_ip_id;
        if (json_object_object_get_ex(ndpiObject, "proto_by_ip_id", &proto_by_ip_id))
        {
            result.proto_by_ip_id = json_object_get_int(proto_by_ip_id);
        }

        json_object* encrypted;
        if (json_object_object_get_ex(ndpiObject, "encrypted", &encrypted))
        {
            result.encrypted = json_object_get_int(encrypted);
        }

        json_object* category_id;
        if (json_object_object_get_ex(ndpiObject, "category_id", &category_id))
        {
            result.category_id = json_object_get_int(category_id);
        }

        json_object* category;
        if (json_object_object_get_ex(ndpiObject, "category", &category))
        {
            result.category = strDuplicate(json_object_get_string(category));
        }

      
        // Extrat http and tls object from json_string_with_http_or_tls_info
        if (json_string_with_http_or_tls_info != NULL)
        {
            json_object * root_http_tls = json_tokener_parse(json_string_with_http_or_tls_info);
            if (root_http_tls != NULL)
            {              
                json_object * ndpiObject_http_tls;
                if (json_object_object_get_ex(root_http_tls, "ndpi", &ndpiObject_http_tls))
                {
                    // Extract http object
                    json_object * httpObject;
                    if (json_object_object_get_ex(ndpiObject_http_tls, "http", &httpObject) &&  json_object_is_type(httpObject, json_type_object))
                    {
                        json_object * request_content_type_object;
                        if (json_object_object_get_ex(httpObject, "request_content_type", &request_content_type_object))
                        {
                            result.http.request_content_type =
                                strDuplicate(json_object_get_string(request_content_type_object));
                        }

                        json_object * content_type_object;
                        if (json_object_object_get_ex(httpObject, "content_type", &content_type_object))
                        {
                            result.http.content_type = strDuplicate(json_object_get_string(content_type_object));
                        }

                        json_object * user_agent_object;
                        if (json_object_object_get_ex(httpObject, "user_agent", &user_agent_object))
                        {
                            result.http.user_agent = strDuplicate(json_object_get_string(user_agent_object));
                        }

                        json_object * filename_object;
                        if (json_object_object_get_ex(httpObject, "filename", &filename_object))
                        {
                            result.http.filename = strDuplicate(json_object_get_string(filename_object));
                        }

                        json_object * code_object;
                        if (json_object_object_get_ex(httpObject, "code", &code_object))
                        {
                            result.http.code = json_object_get_int(code_object);
                        }
                    }
                }

                // Extract tls object
                json_object * tlsObject;
                if (json_object_object_get_ex(ndpiObject_http_tls, "tls", &tlsObject) &&  json_object_is_type(tlsObject, json_type_object))
                {
                    json_object * version_object;
                    if (json_object_object_get_ex(tlsObject, "version", &version_object))
                    {
                        result.tls.version = strDuplicate(json_object_get_string(version_object));
                    }

                    json_object * server_names_object;
                    if (json_object_object_get_ex(tlsObject, "server_names", &server_names_object))
                    {
                        result.tls.server_names = strDuplicate(json_object_get_string(server_names_object));
                    }

                    json_object * ja3_object;
                    if (json_object_object_get_ex(tlsObject, "ja4", &ja3_object))
                    {
                        result.tls.ja4 = strDuplicate(json_object_get_string(ja3_object));
                    }

                    json_object * ja3s_object;
                    if (json_object_object_get_ex(tlsObject, "ja3s", &ja3s_object))
                    {
                        result.tls.ja3s = strDuplicate(json_object_get_string(ja3s_object));
                    }

                    json_object * cipher_object;
                    if (json_object_object_get_ex(tlsObject, "cipher", &cipher_object))
                    {
                        result.tls.cipher = strDuplicate(json_object_get_string(cipher_object));
                    }

                    json_object * issuerDN_object;
                    if (json_object_object_get_ex(tlsObject, "issuerDN", &issuerDN_object))
                    {
                        result.tls.issuerDN = strDuplicate(json_object_get_string(issuerDN_object));
                    }

                    json_object * subjectDN_object;
                    if (json_object_object_get_ex(tlsObject, "subjectDN", &subjectDN_object))
                    {
                        result.tls.subjectDN = strDuplicate(json_object_get_string(subjectDN_object));
                    }
                }
            }

            json_object_put(root_http_tls);
        }
    }

    json_object_put(root);

    return result;
}

unsigned long long int GetFlowId(const char* json_str)
{
    long long int flow_id = RANDOM_UNINITIALIZED_INT_VALUE;
    json_object * root = json_tokener_parse(json_str);
    if (root == NULL)
    {
        fprintf(stderr, "Error parsing JSON\n");
        return RANDOM_UNINITIALIZED_INT_VALUE;
    }

    json_object * flow_id_object;
    if (json_object_object_get_ex(root, "flow_id", &flow_id_object))
    {
        flow_id = json_object_get_int(flow_id_object);
    }

    json_object_put(root);


    return flow_id;
}

static struct Root_data getRootDataStructure(const char* originalJsonStr)
{
    struct Root_data result;
    result.src_ip = NULL;
    result.src_port = RANDOM_UNINITIALIZED_INT_VALUE;
    result.src_packets = RANDOM_UNINITIALIZED_NUMBER_VALUE;
    result.src_bytes = RANDOM_UNINITIALIZED_NUMBER_VALUE;
    result.flow_src_tot_l4_payload_len = RANDOM_UNINITIALIZED_INT_VALUE;
    result.dest_ip = NULL;
    result.dst_port = RANDOM_UNINITIALIZED_INT_VALUE;
    result.des_packets = RANDOM_UNINITIALIZED_NUMBER_VALUE;
    result.des_bytes = RANDOM_UNINITIALIZED_NUMBER_VALUE;
    result.flow_dst_tot_l4_payload_len = RANDOM_UNINITIALIZED_INT_VALUE;
    result.l3_proto = NULL;
    result.ip = RANDOM_UNINITIALIZED_INT_VALUE;
    result.l4_proto = NULL;
    result.proto = NULL;
    result.breed = NULL;
    result.flow_id = RANDOM_UNINITIALIZED_INT_VALUE;
    result.flow_event_id = RANDOM_UNINITIALIZED_NUMBER_VALUE;
    result.packet_id = RANDOM_UNINITIALIZED_NUMBER_VALUE;
    result.event_start = NULL;
    result.event_end = NULL;
    result.event_duration = INVALID_TIMESTAMP;
    result.hostname = NULL;

    // Parse JSON string
    json_object* root = json_tokener_parse(originalJsonStr);
    if (root == NULL)
    {
        fprintf(stderr, "Error parsing JSON\n");
        return result;
    }

    // src_ip and src_port data
    json_object* src_ip;
    if (json_object_object_get_ex(root, "src_ip", &src_ip))
    {
        result.src_ip = strDuplicate(json_object_get_string(src_ip));
    }    

    json_object* src_port;
    if (json_object_object_get_ex(root, "src_port", &src_port))
    {
        result.src_port = json_object_get_int(src_port);
    }

    json_object * flow_src_packets_processed_object;
    if (json_object_object_get_ex(root, "flow_src_packets_processed", &flow_src_packets_processed_object))
    {
        result.src_packets = json_object_get_int(flow_src_packets_processed_object);
    }

    json_object * src2dst_bytes_object;
    if (json_object_object_get_ex(root, "src2dst_bytes", &src2dst_bytes_object))
    {
        result.src_bytes = json_object_get_int(src2dst_bytes_object);
    }
    
    // dest_ip and dst_port data
    json_object* dest_ip;
    if (json_object_object_get_ex(root, "dst_ip", &dest_ip))
    {
        result.dest_ip = strDuplicate(json_object_get_string(dest_ip));
    }
    
    json_object* dst_port;
    if (json_object_object_get_ex(root, "dst_port", &dst_port))
    {
        result.dst_port = json_object_get_int(dst_port);
    }

    json_object * flow_dst_packets_processed_object;
    if (json_object_object_get_ex(root, "flow_dst_packets_processed", &flow_dst_packets_processed_object))
    {
        result.des_packets = json_object_get_int(flow_dst_packets_processed_object);
    }

    json_object * dst2src_bytes_object;
    if (json_object_object_get_ex(root, "dst2src_bytes", &dst2src_bytes_object))
    {
        result.des_bytes = json_object_get_int(dst2src_bytes_object);
    }

    json_object * flow_src_tot_l4_payload_len_object;
    if (json_object_object_get_ex(root, "flow_src_tot_l4_payload_len", &flow_src_tot_l4_payload_len_object))
    {
        result.flow_src_tot_l4_payload_len = json_object_get_int(flow_src_tot_l4_payload_len_object);
    }

    json_object * flow_dst_tot_l4_payload_len_object;
    if (json_object_object_get_ex(root, "flow_dst_tot_l4_payload_len", &flow_dst_tot_l4_payload_len_object))
    {
        result.flow_dst_tot_l4_payload_len = json_object_get_int(flow_dst_tot_l4_payload_len_object);
    }

    // network object
    //json_object* l3_proto;
    //if (json_object_object_get_ex(root, "l3_proto", &l3_proto))
    //{
    //    result.l3_proto = strDuplicate(json_object_get_string(l3_proto));
    //}

    json_object* ip;
    if (json_object_object_get_ex(root, "ip", &ip))
    {
        result.ip = json_object_get_int(ip);
    }
   

    json_object* l4_proto;
    if (json_object_object_get_ex(root, "l4_proto", &l4_proto))
    {
        result.l4_proto = strDuplicate(json_object_get_string(l4_proto));
    }
   
    json_object* proto;
    if (json_object_object_get_ex(root, "proto", &proto))
    {
        result.proto = strDuplicate(json_object_get_string(proto));
    }
    

    json_object* ndpi_object;
    if (json_object_object_get_ex(root, "ndpi", &ndpi_object))
    {
        json_object* breed;
        if (json_object_object_get_ex(ndpi_object, "breed", &breed))
        {
            result.breed = strDuplicate(json_object_get_string(breed));
        }

        json_object* hostname;
        if (json_object_object_get_ex(ndpi_object, "hostname", &hostname))
        {
            result.hostname = strDuplicate(json_object_get_string(hostname));
        }
    }
    

    json_object* flow_id;
    if (json_object_object_get_ex(root, "flow_id", &flow_id))
    {
        result.flow_id = json_object_get_int(flow_id);
    }

    json_object * flow_event_id;
    if (json_object_object_get_ex(root, "flow_event_id", &flow_event_id))
    {
        result.flow_event_id = json_object_get_int(flow_event_id);
    }
  

    json_object * packet_id;
    if (json_object_object_get_ex(root, "packet_id", &packet_id))
    {
        result.packet_id = json_object_get_int(packet_id);
    }
  
  
    // event
    uint64_t start_time = 0;
    uint64_t src_last_pkt_time = 0;
    uint64_t dst_last_pkt_time = 0;

    json_object * flow_first_seen;
    if (json_object_object_get_ex(root, "flow_first_seen", &flow_first_seen))
    {       
        start_time = json_object_get_uint64(flow_first_seen);
        char buf[64];
        convert_usec_to_utc_string(start_time, buf, sizeof(buf));
        result.event_start = strDuplicate(buf);
    }

    json_object * flow_src_last_pkt_time;
    if (json_object_object_get_ex(root, "flow_src_last_pkt_time", &flow_src_last_pkt_time))
    {       
       src_last_pkt_time = json_object_get_uint64(flow_src_last_pkt_time);
    }

    json_object * flow_dst_last_pkt_time;
    if (json_object_object_get_ex(root, "flow_dst_last_pkt_time", &flow_dst_last_pkt_time))
    {
        dst_last_pkt_time = json_object_get_uint64(flow_dst_last_pkt_time);
    }

    if (start_time != 0)
    {       
        char buf[64];
        convert_usec_to_utc_string(max_u64(src_last_pkt_time, dst_last_pkt_time), buf, sizeof(buf));
        result.event_end = strDuplicate(buf);
        result.event_duration = convert_usec_to_nsec(max_u64(src_last_pkt_time, dst_last_pkt_time) - start_time);
    }

    json_object_put(root);

    return result;
}

static char * create_nDPI_Json_String(json_object ** root_object, const struct NDPI_Data * ndpi, int flowRiskIndex)
{
    // Create a new JSON object for ndpi
    //json_object* root = json_object_new_object();
    json_object* ndpiObj = json_object_new_object();

    // Serialize flow_risk

    for (int i = 0; i < (int)ndpi->flow_risk_count; ++i) 
    {
        if (i == flowRiskIndex)
        {
            json_object * riskObj = json_object_new_object();
            json_object_object_add(riskObj, "key", json_object_new_int(ndpi->flow_risk[i].key));
            json_object_object_add(riskObj, "description", json_object_new_string(ndpi_risk2description((ndpi_risk_enum)ndpi->flow_risk[i].key)));
            json_object_object_add(riskObj, "risk", json_object_new_string(ndpi->flow_risk[i].risk));
            json_object_object_add(riskObj, "severity", json_object_new_string(ndpi->flow_risk[i].severity));

            json_object* riskScoreObj = json_object_new_object();
            json_object_object_add(riskScoreObj, "total", json_object_new_int(ndpi->flow_risk[i].risk_score.total));
            json_object_object_add(riskScoreObj, "client", json_object_new_int(ndpi->flow_risk[i].risk_score.client));
            json_object_object_add(riskScoreObj, "server", json_object_new_int(ndpi->flow_risk[i].risk_score.server));
            json_object_object_add(riskObj, "risk_score", riskScoreObj);

            json_object_object_add(ndpiObj, "flow_risk", riskObj);
            
        }
    }

    //  Serialize confidence
    if (ndpi->confidence.value != NULL)
    {
        json_object* confidenceObj = json_object_new_object();
        json_object_object_add(confidenceObj, "key", json_object_new_int(ndpi->confidence.key));
        json_object_object_add(confidenceObj, "value", json_object_new_string(ndpi->confidence.value));       
        json_object_object_add(ndpiObj, "confidence", confidenceObj);       
    }

    // Serialize tls
    BOOL addTLS = FALSE;
    json_object* tlsObj = json_object_new_object();
    if (ndpi->tls.version != NULL)
    {
        json_object_object_add(tlsObj, "version", json_object_new_string(ndpi->tls.version));
        addTLS = TRUE;
    }

    BOOL addClient = FALSE;

    json_object* client = json_object_new_object();
    if (ndpi->tls.server_names != NULL)
    {
        json_object_object_add(client, "server_name", json_object_new_string(ndpi->tls.server_names));
        addClient = TRUE;
        
    }

    if (ndpi->tls.ja4 != NULL)
    {
        json_object_object_add(client, "ja4", json_object_new_string(ndpi->tls.ja4));
        addClient = TRUE;     
    }

    if (addClient)
    {
        json_object_object_add(tlsObj, "client", client);
        addTLS = TRUE;
    }
    else
    {
        json_object_put(client);
    }

    json_object* server = json_object_new_object();
    BOOL addServer = FALSE;
    if (ndpi->tls.ja3s != NULL)
    {
        json_object_object_add(server, "ja4", json_object_new_string(ndpi->tls.ja3s));        
        addServer = TRUE;
    }


    if (ndpi->tls.issuerDN != NULL)
    {
        json_object_object_add(server, "issuer", json_object_new_string(ndpi->tls.issuerDN));      
        addServer = TRUE;
    }

    if (ndpi->tls.subjectDN != NULL)
    {
        json_object_object_add(server, "subject", json_object_new_string(ndpi->tls.subjectDN));
        addServer = TRUE;
    }


    if (addServer)
    {
        json_object_object_add(tlsObj, "server", server);
        addTLS = TRUE;
    }
    else
    {
        json_object_put(server);
    }


    if (ndpi->tls.cipher != NULL)
    {
        json_object_object_add(tlsObj, "cipher", json_object_new_string(ndpi->tls.cipher));
        addTLS = TRUE;
    }

    if (addTLS)
    {
        json_object_object_add(ndpiObj, "tls", tlsObj);
    }
    else
    {
        json_object_put(tlsObj);
    }

    // Serialize http
    BOOL addHTTP = FALSE;
    json_object * httpObj = json_object_new_object();
    if (ndpi->http.request_content_type != NULL && strlen(ndpi->http.request_content_type) > 0)
    {
        json_object_object_add(httpObj, "request_content_type", json_object_new_string(ndpi->http.request_content_type));
        addHTTP = TRUE;
    }

    if (ndpi->http.content_type != NULL && strlen(ndpi->http.content_type) > 0)
    {
        json_object_object_add(httpObj, "content_type", json_object_new_string(ndpi->http.content_type));
        addHTTP = TRUE;
    }

    if (ndpi->http.user_agent != NULL && strlen(ndpi->http.user_agent) > 0)
    {
        json_object_object_add(httpObj, "user_agent", json_object_new_string(ndpi->http.user_agent));
        addHTTP = TRUE;
    }

    if (ndpi->http.filename != NULL && strlen(ndpi->http.filename) > 0)
    {
        json_object_object_add(httpObj, "filename", json_object_new_string(ndpi->http.filename));
        addHTTP = TRUE;
    }

    if (ndpi->http.code != RANDOM_UNINITIALIZED_NUMBER_VALUE && ndpi->http.code != 0)
    {
        json_object_object_add(httpObj, "response.status_code", json_object_new_int(ndpi->http.code));
        addHTTP = TRUE;
    }

    if (addHTTP)
    {
        json_object_object_add(*root_object, "http", httpObj);
    }
    else
    {
        json_object_put(httpObj);
    }

    //Serialize rest of data
    if (ndpi->proto_id != NULL)
    {
        json_object_object_add(ndpiObj, "proto_id", json_object_new_string(ndpi->proto_id));
    }

    if (ndpi->proto_by_ip_id != RANDOM_UNINITIALIZED_INT_VALUE)
    {
        json_object_object_add(ndpiObj, "proto_by_ip_id", json_object_new_int(ndpi->proto_by_ip_id));
    }

    if (ndpi->encrypted != RANDOM_UNINITIALIZED_INT_VALUE)
    {
        json_object_object_add(ndpiObj, "encrypted", json_object_new_int(ndpi->encrypted));
    }

    if (ndpi->category_id != RANDOM_UNINITIALIZED_INT_VALUE)
    {
        json_object_object_add(ndpiObj, "category_id", json_object_new_int(ndpi->category_id));
    }

    if (ndpi->category != NULL)
    {
        json_object_object_add(ndpiObj, "category", json_object_new_string(ndpi->category));
    }

    // Return the serialized JSON string
    char* jsonString = NULL;
    if (json_object_object_length(ndpiObj) > 0)
    {
        jsonString = strDuplicate(json_object_to_json_string(ndpiObj));
    }

   json_object_put(ndpiObj);
    
    // Return the serialized JSON string
    return jsonString;
}

// Function to free memory allocated for NDPI_Data
static void FreeConvertnDPIDataFormat(struct NDPI_Data* ndpiData)
{
    if (ndpiData == NULL) {
        return;
    }

    for (size_t i = 0; i < ndpiData->flow_risk_count; ++i) 
    {
        if (ndpiData->flow_risk[i].risk != NULL)
        {
            free(ndpiData->flow_risk[i].risk);
        }

        if (ndpiData->flow_risk[i].severity != NULL)
        {
            free(ndpiData->flow_risk[i].severity);
        }
    }

    if (ndpiData->flow_risk != NULL)
    {
        free(ndpiData->flow_risk);
    }

    if (ndpiData->confidence.value != NULL)
    {
        free(ndpiData->confidence.value);
    }

    if (ndpiData->tls.version != NULL)
    {
        free(ndpiData->tls.version);
    }

    if (ndpiData->tls.server_names != NULL)
    {
        free(ndpiData->tls.server_names);
    }

    if (ndpiData->tls.ja4 != NULL)
    {
        free(ndpiData->tls.ja4);
    }

    if (ndpiData->tls.ja3s != NULL)
    {
        free(ndpiData->tls.ja3s);
    }

    if (ndpiData->tls.cipher != NULL)
    {
        free(ndpiData->tls.cipher);
    }

    if (ndpiData->tls.subjectDN != NULL)
    {
        free(ndpiData->tls.subjectDN);
    }

    if (ndpiData->tls.issuerDN != NULL)
    {
        free(ndpiData->tls.issuerDN);
    }

    if (ndpiData->proto_id != NULL)
    {
        free(ndpiData->proto_id);
    }

    if (ndpiData->confidence_value != NULL)
    {
        free(ndpiData->confidence_value);
    }

    if (ndpiData->proto_by_ip != NULL)
    {
        free(ndpiData->proto_by_ip);
    }

    if (ndpiData->protocol != NULL)
    {
         free(ndpiData->protocol);
    }

    if (ndpiData->category != NULL)
    {
        free(ndpiData->category);
    }

    if (ndpiData->http.request_content_type != NULL)
    {
        free(ndpiData->http.request_content_type);
    }

    if (ndpiData->http.content_type != NULL)
    {
        free(ndpiData->http.content_type);
    }

    if (ndpiData->http.user_agent != NULL)
    {
        free(ndpiData->http.user_agent);
    }

    if (ndpiData->http.filename != NULL)
    {
        free(ndpiData->http.filename);
    }

}

static void FreeConvertRootDataFormat(struct Root_data* rootData)
{
    if (rootData == NULL) 
    {
        return;
    }

    if (rootData->src_ip != NULL)
    {
        free(rootData->src_ip);
    }

    //if (rootData->src_port != NULL)
    //{
    //    free(rootData->src_port);
    //}

    if (rootData->dest_ip != NULL)
    {
        free(rootData->dest_ip);
    }

    //if (rootData->dst_port != NULL)
    //{
    //    free(rootData->dst_port);
    //}

    //if (rootData->l3_proto != NULL)
    //{
    //    free(rootData->l3_proto);
    //}

    if (rootData->l4_proto != NULL)
    {
        free(rootData->l4_proto);
    }

    if (rootData->proto != NULL)
    {
        free(rootData->proto);
    }


    if (rootData->breed != NULL)
    {
        free(rootData->breed);
    }

    if (rootData->event_start != NULL)
    {
        free(rootData->event_start);
    }

    if (rootData->event_end != NULL)
    {
        free(rootData->event_end);
    }

    //if (rootData->event_duration != NULL)
    //{
    //    free(rootData->event_duration);
    //}

    if (rootData->hostname != NULL)
    {
        free(rootData->hostname);
    }

}

static int add_nDPI_Data(json_object ** root_object, struct NDPI_Data nDPIStructure, int flowRiskIndex)
{
    char * nDPIJsonString = create_nDPI_Json_String(root_object, &nDPIStructure, flowRiskIndex);
    if (nDPIJsonString == NULL)
    {
        // Ashwani
        //fprintf(stderr, "create_nDPI_Json_String routine returned empty string: Error parsing new ndpi JSON\n");
        return -1;
    }

    json_object* newNDPIObject = json_tokener_parse(nDPIJsonString);
    if (newNDPIObject == NULL)
    {
        fprintf(stderr, "Error parsing JSON string\n");
        free(nDPIJsonString); // Free allocated memory for JSON string
        return -1;
    }

    json_object_object_add(*root_object, "ndpi", newNDPIObject);
    free(nDPIJsonString); // Free allocated memory for JSON string if not needed anymore
    return 1;
}

/*--------------------------------------------------------------------------------------------------------------------------------------*/
static void add_Root_Data(json_object ** root_object,
                          struct Root_data rootDataStructure,
                          int flowRiskCount,
                          char * proto_by_ip,
                          char * protocol)
{
    json_object* src_object = json_object_new_object();

    BOOL addSrc = FALSE;
    if (rootDataStructure.src_ip != NULL)
    {
        json_object_object_add(src_object, "ip", json_object_new_string(rootDataStructure.src_ip));
        addSrc = TRUE;
    }

    if (rootDataStructure.src_port != RANDOM_UNINITIALIZED_INT_VALUE)
    {
        json_object_object_add(src_object, "port", json_object_new_int(rootDataStructure.src_port));
        addSrc = TRUE;
    }

    if (rootDataStructure.src_packets != RANDOM_UNINITIALIZED_NUMBER_VALUE)
    {
        json_object_object_add(src_object, "packets", json_object_new_int(rootDataStructure.src_packets));
        addSrc = TRUE;
    }

    if (rootDataStructure.src_bytes != RANDOM_UNINITIALIZED_NUMBER_VALUE)
    {
        json_object_object_add(src_object, "bytes", json_object_new_int(rootDataStructure.src_bytes));
        addSrc = TRUE;
    }

    if (rootDataStructure.flow_src_tot_l4_payload_len != RANDOM_UNINITIALIZED_INT_VALUE)
    {
        json_object_object_add(src_object,
                               "src2dst_goodput_bytes",
                               json_object_new_int(rootDataStructure.flow_src_tot_l4_payload_len));
        addSrc = TRUE;
    }

    if (addSrc)
    {
        json_object_object_add(*root_object, "source", src_object);
    }


    BOOL addDest = FALSE;
    json_object* dest_object = json_object_new_object();

    if (rootDataStructure.dest_ip != NULL)
    {
        json_object_object_add(dest_object, "ip", json_object_new_string(rootDataStructure.dest_ip));
        addDest = TRUE;
    }

    if (rootDataStructure.dst_port != RANDOM_UNINITIALIZED_INT_VALUE)
    {
        json_object_object_add(dest_object, "port", json_object_new_int(rootDataStructure.dst_port));
        addDest = TRUE;
    }

    if (rootDataStructure.des_packets != RANDOM_UNINITIALIZED_NUMBER_VALUE)
    {
        json_object_object_add(dest_object, "packets", json_object_new_int(rootDataStructure.des_packets));
        addDest = TRUE;
    }

    if (rootDataStructure.des_bytes != RANDOM_UNINITIALIZED_NUMBER_VALUE)
    {
        json_object_object_add(dest_object, "bytes", json_object_new_int(rootDataStructure.des_bytes));
        addDest = TRUE;
    }

    if (rootDataStructure.flow_dst_tot_l4_payload_len != RANDOM_UNINITIALIZED_INT_VALUE)
    {
        json_object_object_add(dest_object,
                               "dst2src_goodput_bytes",
                               json_object_new_int(rootDataStructure.flow_dst_tot_l4_payload_len));
        addDest = TRUE;
    }

    if (addDest)
    {
        json_object_object_add(*root_object, "destination", dest_object);
    }

    json_object* network_object = json_object_new_object();
    BOOL addNetwork = FALSE;

    if (rootDataStructure.ip != RANDOM_UNINITIALIZED_INT_VALUE)
    {
        if (rootDataStructure.ip == 4)
        {
            json_object_object_add(network_object, "type", json_object_new_string("ipv4"));
            addNetwork = TRUE;
        }

        if (rootDataStructure.ip == 6)
        {
            json_object_object_add(network_object, "type", json_object_new_string("ipv6"));
            addNetwork = TRUE;
        }
    }

    if (rootDataStructure.l4_proto != NULL)
    {
        json_object_object_add(network_object, "transport", json_object_new_string(rootDataStructure.l4_proto));
        addNetwork = TRUE;
    }

    if (rootDataStructure.proto != NULL)
    {
        json_object_object_add(network_object, "application", json_object_new_string(rootDataStructure.proto));
        addNetwork = TRUE;
    }

    if (proto_by_ip != NULL)
    {
        json_object_object_add(network_object, "application", json_object_new_string(proto_by_ip));
        addNetwork = TRUE;
    }

    if (protocol != NULL)
    {
        json_object_object_add(network_object, "protocol", json_object_new_string(protocol));
        addNetwork = TRUE;
    }

    if (addNetwork)
    {
        json_object_object_add(*root_object, "network", network_object);
    }
   
    if (rootDataStructure.breed != NULL)
    {
        json_object* breed_object = json_object_new_object();
        json_object_object_add(breed_object, "category", json_object_new_string(rootDataStructure.breed));
        json_object_object_add(*root_object, "rule", breed_object);
    }

    // Event starts here
    json_object * event_object = json_object_new_object();
    if (rootDataStructure.event_start != NULL)
    {
        json_object_object_add(event_object, "start", json_object_new_string(rootDataStructure.event_start));
    }

    if (rootDataStructure.event_end != NULL)
    {
        json_object_object_add(event_object, "end", json_object_new_string(rootDataStructure.event_end));
    }

    if (rootDataStructure.event_duration != INVALID_TIMESTAMP)
    {
        json_object_object_add(event_object, "duration", json_object_new_uint64(rootDataStructure.event_duration));
    }

    if (flowRiskCount > 0)
    {
        json_object_object_add(event_object, "kind", json_object_new_string("alert"));
    }
    else
    {
        json_object_object_add(event_object, "kind", json_object_new_string("event"));
    }

    json_object_object_add(*root_object, "event", event_object);
    
    // Flow starts here
    if (rootDataStructure.flow_id != RANDOM_UNINITIALIZED_INT_VALUE)
    {
        json_object* flow_id_object = json_object_new_object();
        json_object_object_add(flow_id_object, "id", json_object_new_int(rootDataStructure.flow_id));
        json_object_object_add(*root_object, "flow", flow_id_object);
    }

    // hostname
    if (rootDataStructure.hostname != NULL)
    {
        json_object* full_object = json_object_new_object();
        json_object_object_add(full_object, "full", json_object_new_string(rootDataStructure.hostname));
        json_object_object_add(*root_object, "url", full_object);    
    }   
}

void ConvertnDPIDataFormat(const char * originalJsonStr,
                           const char * const json_string_with_http_or_tls_info,
                           int flowRiskIndex,
                           char ** converted_json_str,
                           int * createAlert)
{
   
    struct NDPI_Data ndpiData = getnDPIStructure(originalJsonStr, json_string_with_http_or_tls_info);

    *createAlert = ndpiData.flow_risk_count;

    json_object* root_object = json_object_new_object();
    struct Root_data rootData;
    if (add_nDPI_Data(&root_object, ndpiData, flowRiskIndex))
    {
        rootData = getRootDataStructure(originalJsonStr);
        bool filterd = matchEntryInParamsVector(rootData.src_ip, rootData.dest_ip, rootData.dst_port);
        if (!filterd)
        {
            add_Root_Data(&root_object, rootData, ndpiData.flow_risk_count, ndpiData.proto_by_ip, ndpiData.protocol);
            *converted_json_str = strDuplicate(json_object_to_json_string(root_object));
        }
        else
        {
            printf("Flow Filtered: src_ip = %s, dest_ip = %s, destination_port = %d", rootData.src_ip, rootData.dest_ip, rootData.dst_port);
        }
    }

    FreeConvertnDPIDataFormat(&ndpiData);
    json_object_put(root_object);
    FreeConvertRootDataFormat(&rootData);
}

void GetFlowRiskArraySizeAndFlowId(char * alertStringWithFlowRiskArray, int * flow_risk_array_size, int* flow_id)
{
    // Parse JSON string to JSON object
    *flow_risk_array_size = 0;
    struct json_object * parsed_json_object = json_tokener_parse(alertStringWithFlowRiskArray);
    if (!parsed_json_object)
    {
        fprintf(stderr, "Error parsing JSON\n");
        return ;
    }

    // Navigate to the `ndpi` and `flow_risk` fields
    struct json_object * ndpi_obj = NULL;
    struct json_object * flow_risk_array = NULL;
    if (!json_object_object_get_ex(parsed_json_object, "ndpi", &ndpi_obj) || !json_object_object_get_ex(ndpi_obj, "flow_risk", &flow_risk_array))
    {
        fprintf(stderr, "Missing 'ndpi' or 'flow_risk' field\n");
        json_object_put(parsed_json_object); // Free parsed JSON object
        return ;
    }

    // Check if `flow_risk` is an array and the index is valid
    if (!json_object_is_type(flow_risk_array, json_type_array))
    {
        fprintf(stderr, "'flow_risk' is not an array\n");
        json_object_put(parsed_json_object); // Free parsed JSON object
        return ;
    }

    *flow_risk_array_size = json_object_array_length(flow_risk_array);

    json_object * flow_id_object;
    if (json_object_object_get_ex(parsed_json_object, "flow_id", &flow_id_object))
    {
        *flow_id = json_object_get_int(flow_id_object);
    }
}

void GetAlertJsonStringWithFlowRisk(char * alertStringWithFlowRiskArray, char ** converted_json_str, int flow_risk_index)
{
    // logger(0, "GetAlertJsonStringWithFlowRisk START");
    // logger(0, "alertStringWithFlowRiskArray %s", alertStringWithFlowRiskArray);
    // Parse JSON string to JSON object
    struct json_object * parsed_json_object = json_tokener_parse(alertStringWithFlowRiskArray);

    if (!parsed_json_object)
    {
        fprintf(stderr, "Error parsing JSON\n");
        return ;
    }



    // Navigate to the `ndpi` and `flow_risk` fields
    struct json_object * ndpi_obj = NULL;
    struct json_object * flow_risk_array = NULL;
    if (!json_object_object_get_ex(parsed_json_object, "ndpi", &ndpi_obj) ||
        !json_object_object_get_ex(ndpi_obj, "flow_risk", &flow_risk_array))
    {
        fprintf(stderr, "Missing 'ndpi' or 'flow_risk' field\n");
        json_object_put(parsed_json_object); // Free parsed JSON object
        return ;
    }

  

    // Check if `flow_risk` is an array and the index is valid
    if (!json_object_is_type(flow_risk_array, json_type_array))
    {
        fprintf(stderr, "'flow_risk' is not an array\n");
        json_object_put(parsed_json_object); // Free parsed JSON object
        return ;
    }




    int array_len = json_object_array_length(flow_risk_array);
    if (flow_risk_index < 0 || flow_risk_index >= array_len)
    {
        fprintf(stderr, "Index out of bounds\n");
        json_object_put(parsed_json_object); // Free parsed JSON object
        return ;
    }


    // Get the specified object from the array
    struct json_object * selected_risk_obj = json_object_array_get_idx(flow_risk_array, flow_risk_index);
   

    // Clone the selected object to avoid modifying the array itself
    struct json_object * flow_risk_obj = json_object_get(selected_risk_obj);


    // Replace `flow_risk` array with the single selected object
    json_object_object_del(ndpi_obj, "flow_risk");
 
    json_object_object_add(ndpi_obj, "flow_risk", flow_risk_obj);


    // Convert modified JSON back to string
    const char * modified_json_str = json_object_to_json_string(parsed_json_object);
   

    // Duplicate the string so it can be returned (since original will be freed)
    *converted_json_str = strdup(modified_json_str);
 

    // Clean up
    json_object_put(parsed_json_object);  
    
}

void DeletenDPIRisk(char* originalJsonStr, char** converted_json_str)
{
    json_object* root = json_tokener_parse(originalJsonStr);
    if (root == NULL)
    {
        fprintf(stderr, "Error parsing JSON\n");
        return;
    }

    json_object* ndpiObject;
    if (json_object_object_get_ex(root, "ndpi", &ndpiObject))
    {
        json_object_object_del(ndpiObject, "flow_risk");
        if (json_object_object_length(ndpiObject) < 1)
        {
            json_object_object_del(root, "ndpi");
        }       
    }

    json_object* eventObject;
    if (json_object_object_get_ex(root, "event", &eventObject))
    {
        json_object_object_del(eventObject, "kind");
        json_object_object_add(eventObject, "kind", json_object_new_string("event"));
    }

    *converted_json_str = strdup(json_object_to_json_string(root));
    json_object_put(root);

}

int CheckSRCIPField(const char * json_str)
{
    // Parse the JSON string
    json_object * parsed_json_object = json_tokener_parse(json_str);
    if (parsed_json_object == NULL)
    {
        printf("Error: in parsing JSON string\n");
        return 0; // Parsing failed, assume src_ip is not present
    }

    // Check for the src_ip field
    json_object * srcIpObject;
    if (json_object_object_get_ex(parsed_json_object, "src_ip", &srcIpObject))
    {
        json_object_put(parsed_json_object); // Free the parsed JSON object
        return 1;                     // src_ip field is present
    }

    json_object_put(parsed_json_object); // Free the parsed JSON object
    return 0;                     // src_ip field is not present
    
}


// Function to update "xfer" field in json1 if values in json2 are greater
void UpdateXferIfGreater(char * existing_json_str, const char * new_json_str, char ** converted_json_str)
{
    json_object * existing_json_object = json_tokener_parse(existing_json_str);
    if (existing_json_object == NULL)
    {
        return;
    }

    json_object * new_json_object = json_tokener_parse(new_json_str);
    if (new_json_object == NULL)
    {
        return;
    }

    // Extract the "source" and "destination" fields from both JSON objects
    struct json_object *source1, *destination1, *source2, *destination2;
    json_object_object_get_ex(existing_json_object, "source", &source1);
    json_object_object_get_ex(existing_json_object, "destination", &destination1);
    json_object_object_get_ex(new_json_object, "source", &source2);
    json_object_object_get_ex(new_json_object, "destination", &destination2);

    // Extract the "packets" and "bytes" from both "source" and "destination"
    int src1_packets = json_object_get_int(json_object_object_get(source1, "packets"));
    int src1_bytes = json_object_get_int(json_object_object_get(source1, "bytes"));
    int dst1_packets = json_object_get_int(json_object_object_get(destination1, "packets"));
    int dst1_bytes = json_object_get_int(json_object_object_get(destination1, "bytes"));

    int src2_packets = json_object_get_int(json_object_object_get(source2, "packets"));
    int src2_bytes = json_object_get_int(json_object_object_get(source2, "bytes"));
    int dst2_packets = json_object_get_int(json_object_object_get(destination2, "packets"));
    int dst2_bytes = json_object_get_int(json_object_object_get(destination2, "bytes"));

    json_object_object_add(source1,
                           "packets",
                           json_object_new_int(src2_packets > src1_packets ? src2_packets : src1_packets));

    json_object_object_add(source1,
                           "bytes",
                           json_object_new_int(src2_bytes > src1_bytes ? src2_bytes : src1_bytes));

    json_object_object_add(destination1,
                           "packets",
                           json_object_new_int(dst2_packets > dst1_packets ? dst2_packets : dst1_packets));
    json_object_object_add(destination1,
                           "bytes",
                           json_object_new_int(dst2_bytes > dst1_bytes ? dst2_bytes : dst1_bytes));

    // update event field
    json_object *existing_event_obj, *new_event_obj;
    json_object_object_get_ex(existing_json_object, "event", &existing_event_obj);
    json_object_object_get_ex(new_json_object, "event", &new_event_obj);

    // update event.end field
    struct json_object *existing_event_end, *new_event_end;
    json_object_object_get_ex(existing_event_obj, "end", &existing_event_end);
    json_object_object_get_ex(new_event_obj, "end", &new_event_end);
    char * existing_event_end_string = strDuplicate(json_object_get_string(existing_event_end));
    char * new_event_end_string = strDuplicate(json_object_get_string(new_event_end));

    if (strcmp(new_event_end_string, existing_event_end_string) > 0)
    {
        json_object_object_del(existing_event_obj, "end");
        json_object_object_add(existing_event_obj, "end", json_object_new_string(new_event_end_string));
    }

    free(existing_event_end_string);
    free(new_event_end_string);

    // update event.duration field
    struct json_object *existing_event_duration, *new_event_duration;
    json_object_object_get_ex(existing_event_obj, "duration", &existing_event_duration);
    json_object_object_get_ex(new_event_obj, "duration", &new_event_duration);
    unsigned long existing_event_duration_value = json_object_get_double(existing_event_duration);
    unsigned long new_event_duration_value = json_object_get_double(new_event_duration);

    if (new_event_duration_value > existing_event_duration_value)
    {
        json_object_object_del(existing_event_obj, "duration");
        json_object_object_add(existing_event_obj, "duration", json_object_new_int64(new_event_duration_value));
    }

    // update http fields
    json_object *existing_http_obj, *new_http_obj;
    if (json_object_object_get_ex(existing_json_object, "http", &existing_http_obj))
    {
        if (json_object_object_get_ex(new_json_object, "http", &new_http_obj))
        {
             // update event.request_content_type field
             struct json_object *existing_request_content_type, *new_request_content_type;
             if (json_object_object_get_ex(existing_http_obj, "request_content_type", &existing_request_content_type))
             {
                 if (json_object_object_get_ex(new_http_obj, "request_content_type", &new_request_content_type))
                 {
                     char * existing_request_content_type_string =  strDuplicate(json_object_get_string(existing_event_end));
                     char * new_request_content_type_string = strDuplicate(json_object_get_string(new_event_end));

                     if (strcmp(new_request_content_type_string, existing_request_content_type_string) > 0)
                     {
                         json_object_object_del(existing_http_obj, "request_content_type");
                         json_object_object_add(existing_http_obj, "request_content_type",  json_object_new_string(new_request_content_type_string));
                     }

                     free(existing_request_content_type_string);
                     free(new_request_content_type_string);
                 }
             }

             // update event.content_type field
             struct json_object *existing_content_type, *new_content_type;
             if (json_object_object_get_ex(existing_http_obj, "content_type", &existing_content_type))
             {
                 if (json_object_object_get_ex(new_http_obj, "content_type", &new_content_type))
                 {
                     char * existing_content_type_string =  strDuplicate(json_object_get_string(existing_event_end));
                     char * new_content_type_string = strDuplicate(json_object_get_string(new_event_end));

                     if (strcmp(new_content_type_string, existing_content_type_string) > 0)
                     {
                         json_object_object_del(existing_http_obj, "content_type");
                         json_object_object_add(existing_http_obj, "content_type", json_object_new_string(new_content_type_string));
                     }

                     free(existing_content_type_string);
                     free(new_content_type_string);
                 }
             }

             // update event.user_agent field
             struct json_object *existing_user_agent, *new_user_agent;
             if (json_object_object_get_ex(existing_http_obj, "user_agent", &existing_user_agent))
             {
                 if (json_object_object_get_ex(new_http_obj, "user_agent", &new_user_agent))
                 {
                     char* existing_user_agent_string = strDuplicate(json_object_get_string(existing_event_end));
                     char* new_user_agent_string = strDuplicate(json_object_get_string(new_event_end));

                     if (strcmp(new_user_agent_string, existing_user_agent_string) > 0)
                     {
                         json_object_object_del(existing_http_obj, "user_agent");
                         json_object_object_add(existing_http_obj, "user_agent",  json_object_new_string(new_user_agent_string));
                     }

                     free(existing_user_agent_string);
                     free(new_user_agent_string);
                 }
             }

             // update event.filename field
             struct json_object *existing_filename, *new_filename;
             if (json_object_object_get_ex(existing_http_obj, "filename", &existing_filename))
             {
                 if (json_object_object_get_ex(new_http_obj, "filename", &new_filename))
                 {
                     char * existing_filename_string = strDuplicate(json_object_get_string(existing_event_end));
                     char * new_filename_string = strDuplicate(json_object_get_string(new_event_end));

                     if (strcmp(new_filename_string, existing_filename_string) > 0)
                     {
                         json_object_object_del(existing_http_obj, "filename");
                         json_object_object_add(existing_http_obj, "filename",  json_object_new_string(new_filename_string));
                     }

                     free(existing_filename_string);
                     free(new_filename_string);
                 }
             }

             // update event.response_status_code field
             struct json_object *existing_response_status_code, *new_response_status_code;
             if (json_object_object_get_ex(existing_http_obj, "response.status_code", &existing_response_status_code))
             {
                 if (json_object_object_get_ex(new_http_obj, "response.status_code", &new_response_status_code))
                 {
                     unsigned long existing_response_status_code_value = json_object_get_int(existing_response_status_code);
                     unsigned long new_response_status_code_value = json_object_get_int(new_response_status_code);

                     if (new_response_status_code_value > existing_response_status_code_value)
                     {
                         json_object_object_del(existing_http_obj, "response.status_code");
                         json_object_object_add(existing_http_obj, "response.status_code", json_object_new_int64(new_response_status_code_value));
                     }
                 }
             }
        }
    }

    *converted_json_str = strdup(json_object_to_json_string(existing_json_object));
  
    json_object_put(existing_json_object);
    json_object_put(new_json_object);
}

/*--------------------------------------------------------------------------------------------------------------------------*/
// Function to traverse JSON and create an array of SkipParameters
static void traverseJsonObject(json_object * jsonObj, struct SkipParameters ** paramsVector, int * vectorSize)
{
    json_object_object_foreach(jsonObj, key, val)
    {
        enum json_type type = json_object_get_type(val);

        // Look for the "skipParameters" array only
        if (type == json_type_array && strcmp(key, "skipParameters") == 0)
        {
            int arrayLength = json_object_array_length(val);
            for (int i = 0; i < arrayLength; ++i)
            {
                *vectorSize += 1;
                *paramsVector = realloc(*paramsVector, (*vectorSize) * sizeof(struct SkipParameters));
                (*paramsVector)[*vectorSize - 1].sourceIP = strdup("NOT_SET");
                (*paramsVector)[*vectorSize - 1].destinationIP = strdup("NOT_SET");
                (*paramsVector)[*vectorSize - 1].destinationPort = -1;

                json_object * arrayElement = json_object_array_get_idx(val, i);
                // Populate each SkipParameters entry
                json_object_object_foreach(arrayElement, k, v)
                {
                    enum json_type t = json_object_get_type(v);
                    if (t == json_type_string)
                    {
                        if (strcmp(k, "sourceIP") == 0)
                        {
                            free((*paramsVector)[*vectorSize - 1].sourceIP);
                            (*paramsVector)[*vectorSize - 1].sourceIP = strdup(json_object_get_string(v));
                        }
                        else if (strcmp(k, "destinationIP") == 0)
                        {
                            free((*paramsVector)[*vectorSize - 1].destinationIP);
                            (*paramsVector)[*vectorSize - 1].destinationIP = strdup(json_object_get_string(v));
                        }
                    }
                    else if (t == json_type_int)
                    {
                        if (strcmp(k, "destinationPort") == 0)
                        {
                            (*paramsVector)[*vectorSize - 1].destinationPort = json_object_get_int(v);
                        }
                    }
                }
            }
        }
        else if (type == json_type_object)
        {
            traverseJsonObject(val, paramsVector, vectorSize); // Recursively check inside nested objects
        }
    }
}


/*--------------------------------------------------------------------------------------------------------------------------*/
static void printParamsVector(const struct SkipParameters * paramsVector, int vectorSize)
{
    printf("\tParams Vector:\n");

    int i = 0;
    for (i = 0; i < vectorSize; ++i)
    {
        printf("\tEntry %d:\n", i + 1);
        printf("\t\tSource IP: %s\n", paramsVector[i].sourceIP);
        printf("\t\tDestination IP: %s\n", paramsVector[i].destinationIP);

        if (paramsVector[i].destinationPort != -1)
        {
            printf("\t\tDestination Port: %d\n", paramsVector[i].destinationPort);
        }
        else
        {
            printf("\t\tDestination Port: NOT_SET\n");
        }

        printf("\n");
    }
}

/*--------------------------------------------------------------------------------------------------------------------------*/
static bool matchEntryInParamsVector(const char* srcIP, const char* destIP, int destPort) 
{
    int i = 0;
    for (i = 0; i < vectorSize; ++i) 
    {
        // Check if sourceIP matches
        if (strcmp(paramsVector[i].sourceIP, "NOT_SET") != 0 && strcmp(paramsVector[i].sourceIP, srcIP) != 0) 
        {
            continue;
        }

        // Check if destinationIP matches
        if (strcmp(paramsVector[i].destinationIP, "NOT_SET") != 0 && strcmp(paramsVector[i].destinationIP, destIP) != 0) 
        {
            continue;
        }

        // Check if destinationPort matches (if present)
        if (paramsVector[i].destinationPort != -1 && paramsVector[i].destinationPort != destPort) 
        {
            continue;
        }

        // All criteria match, return true
        return true;
    }

    // No matching entry found
    return false;
}


/*--------------------------------------------------------------------------------------------------------------------------*/
void ReadNdpidConfigurationFilterFile(const char * filename, int print_to_console)
{
    if (print_to_console >= 1)
    {
        printf("Reading configuration filter data from JSON file: %s\n", filename);
    }

    if (!hasAlreadyReadLogFile)
    {
        FILE * fp = fopen(filename, "r");
        if (!fp)
        {
            printf("ERROR: opening JSON config file\n");
            return;
        }

        fseek(fp, 0, SEEK_END);
        long file_size = ftell(fp);
        rewind(fp);

        char * file_contents = malloc(file_size + 1);
        if (!file_contents)
        {
            printf("ERROR: Memory allocation failed\n");
            fclose(fp);
            return;
        }

        size_t read_bytes = fread(file_contents, 1, file_size, fp);
        if (read_bytes != (size_t)file_size)
        {
            printf("ERROR: fread failed or incomplete (expected %ld bytes, got %zu)\n", file_size, read_bytes);
            free(file_contents);
            return;
        }

        file_contents[file_size] = '\0';
        fclose(fp);

        struct json_object * parsed_json = json_tokener_parse(file_contents);
        free(file_contents);

        if (!parsed_json)
        {
            printf("ERROR: Failed to parse JSON\n");
            return;
        }


        traverseJsonObject(parsed_json, &paramsVector, &vectorSize);

        if (print_to_console >= 1)
        {
            printParamsVector(paramsVector, vectorSize);
        }

        // Free the JSON object
        json_object_put(parsed_json);
        hasAlreadyReadLogFile = true;     
    }
}



