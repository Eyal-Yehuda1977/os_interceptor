#include <stdio.h>







int init_os_interceptor() {




	return 0;
}


int destroy_os_interceptor() {



	return 0;
}




static void signal_handler(int signal) {

  if ((signal == SIGTERM) || (signal == SIGINT) ) 
             destroy_os_interceptor();
  else if((signal == SIGHUP)) 
	  ; // reload configurations 
}




int main() {


	  signal(SIGINT,   signal_handler);
	  signal(SIGTERM,  signal_handler);  
	  signal(SIGHUP,   signal_handler);


	  init_os_interceptor();




	  destroy_os_interceptor();

	return 0;
}
