#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#define RANDOM_UNINITIALIZED_NUMBER_VALUE 0xFFFFFFFF // UINT_MAX (4294967295)
#define RANDOM_UNINITIALIZED_INT_VALUE -84742891
#define INVALID_FLOW_ID UINT64_MAX

// New APIs for flow direction tracking
void StoreOrUpdateFlowDirection(const char *json_msg);
char *UpdateFlowDirectionIfSwapped(const char *json_msg);
// Fills missing HTTP fields in json_msg from stored info, returns new string if updated, else NULL
char *FillMissingHttpFieldsFromFlowInfo(const char *json_msg);
void ClearFlowDirectionMap(void)

void ConvertnDPIDataFormat(const char * json_str, const char * const json_string_with_http_or_tls_info, int flowRiskIndex, char ** converted_json_str, int * create_alert);
void DeletenDPIRisk(char* jsonStr, char** converted_json_str);
void GetAlertJsonStringWithFlowRisk(char * alertStringWithFlowRiskArray, char ** converted_json_str, int flow_risk_index);
void GetFlowRiskArraySizeAndFlowId(char * alertStringWithFlowRiskArray, int * flow_risk_array_size, uint64_t * flow_id);
int CheckSRCIPField(const char * json_str);
void UpdateXferIfGreater(char * json_str1, const char * json_str2, char ** converted_json_str);
uint64_t GetFlowId(const char * json_str);
void ReadNdpidConfigurationFilterFile(const char * filename, int print_to_console);

#ifdef __cplusplus
}
#endif