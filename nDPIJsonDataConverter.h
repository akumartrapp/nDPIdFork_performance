#ifdef __cplusplus
extern "C" {
#endif

void ConvertnDPIDataFormat(char * jsonStr,
                               char ** converted_json_str,
                               int * createAlert,
                               unsigned long long int * flow_id,
                               unsigned int * flow_event_id,
                               unsigned int * packet_id,
                               char * current_pcap_file);
void DeletenDPIRisk(char* jsonStr, char** converted_json_str);
void GetAlertJsonStringWithFlowRisk(char * alertStringWithFlowRiskArray, char ** converted_json_str, int flow_risk_index);
void GetFlowRiskArraySizeAndFlowId(char * alertStringWithFlowRiskArray, int * flow_risk_array_size, int* flow_id);
int CheckSRCIPField(const char * json_str);
void UpdateXferIfGreater(char * json_str1, const char * json_str2, char ** converted_json_str);

#ifdef __cplusplus
}
#endif