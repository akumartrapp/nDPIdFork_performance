#ifdef __cplusplus
extern "C" {
#endif

void ConvertnDPIDataFormat(const char * json_str, const char * const json_string_with_http_or_tls_info, int flowRiskIndex, char ** converted_json_str, int * create_alert);
void DeletenDPIRisk(char* jsonStr, char** converted_json_str);
void GetAlertJsonStringWithFlowRisk(char * alertStringWithFlowRiskArray, char ** converted_json_str, int flow_risk_index);
void GetFlowRiskArraySizeAndFlowId(char * alertStringWithFlowRiskArray, int * flow_risk_array_size, int* flow_id);
int CheckSRCIPField(const char * json_str);
void UpdateXferIfGreater(char * json_str1, const char * json_str2, char ** converted_json_str);
unsigned long long int GetFlowId(const char * json_str);
void ReadNdpidConfigurationFilterFile(const char * filename, bool print_to_console);

#ifdef __cplusplus
}
#endif