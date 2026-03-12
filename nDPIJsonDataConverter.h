
#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#define RANDOM_UNINITIALIZED_NUMBER_VALUE 0xFFFFFFFF // UINT_MAX (4294967295)
#define RANDOM_UNINITIALIZED_INT_VALUE -84742891
#define INVALID_FLOW_ID UINT64_MAX


// New APIs for flow direction tracking
// Accessor APIs for flow_direction_map
typedef struct {
	char src_ip[64];
	int src_port;
	char dst_ip[64];
	int dst_port;
	int swapped;
	char *json_str; // Store full JSON string
} flow_direction_info_t;

typedef struct {
	uint64_t flow_id;
	flow_direction_info_t info;
} flow_direction_map_entry_t;
const flow_direction_map_entry_t *GetFlowDirectionMap(int *size);
char* StoreOrUpdateFlowDirection(const char *json_msg);
char *UpdateFlowDirectionIfSwapped(const char *json_msg);
void UpdateFlowDirectionJson(const char *json_msg);
void ClearFlowDirectionMap(void);
int RemoveFlowDirectionEntry(uint64_t flow_id);

void ConvertnDPIDataFormat(const char * json_str, int flowRiskIndex, char ** converted_json_str, int * create_alert);
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