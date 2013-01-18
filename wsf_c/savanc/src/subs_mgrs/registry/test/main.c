int add_subscriber();
void get_all_subscribers();
void remove_subscriber();
void get_all_subscribers_for_topic();
char *test_endpoint_serialize();
void test_endpoint_deserialize();

int main(int argc, char** argv)
{
    char *content = 0;

	add_subscriber();
	get_all_subscribers();
    /*get_all_subscribers_for_topic("/weather/4/system.subscriptions");*/
    /*content = test_endpoint_serialize();
    test_endpoint_deserialize(content);*/
    return 0;
}
