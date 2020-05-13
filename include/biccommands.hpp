
/*  NetFun from BIC */
#define NETFUN_FB_OEM_BIC 0x38


/*  Commands from BIC */
enum fb_oem_bic
{
	CMD_OEM_BIC_INFO = 0x1
};

/*  IPMI request packet from BIC */
typedef struct
{
  uint8_t data[4];

  struct 
  {
    uint8_t netfn;
    uint8_t cmd;
    std::vector<int> data;
  }ipmi_req; 

}ipmi_bic_req_t;
