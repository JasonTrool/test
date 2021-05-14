#include "tcp_dump_parser.h"

#include <iostream>

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        std::cout << "Usage: ./tcpsesscount <file_path>" << std::endl;
        return 1;
    }
    TcpDumpParser parser(argv[1]);
    if (!parser.has_error())
    {
        parser.parse();
    }
    return 0;
}
