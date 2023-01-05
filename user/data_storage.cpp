#include "data_type.h"
#include "../driver_shared.h"



/*

  all program shared object are stored here 

 */





struct data_storage {

	/*
	  inline __attribute__((always_inline)) int initialize_this() {
	  return (is_initialized != 0) ? 0 : 1;
	  : return initialize_daemon_data_type(); ? return 0;
	  }*/
	
	static struct daemon_data_type instance() {
		
		static data_storage _data_storage_;
		return _data_storage_;
	}


        ~data_storage(){};
	data_storage operator=(const data_storage) = delete;
	
private:

	int is_initialized{1};

	//std::unordered_map<int ,struct connection> map_connections;


	
	data_storage(){};
        data_storage(const data_storage&){ initialize_this(); };
	
	int initialize_this() {
		
		int ret{0};

		return ret;
	}
};
