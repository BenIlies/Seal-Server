#include "seal/seal.h"
#include <iostream>
#include <string>
#include <WS2tcpip.h>
#include <vector>
#define STOP_MSG "Stop data"
#define END_BUFFER "End of buffer"
#define SIZE_BUFFER 8192
#pragma comment (lib, "ws2_32.lib")

/*
	Important :
	There might be an issue appearing if one of the buffer sent over the tcp connection is a multiple of SIZE_BUFFER.
	Hence, in the future it could be interesting to fix it
*/

using namespace seal;

int main()
{
	#ifndef SEAL_USE_ZLIB
		std::cerr << "ZLIB support is not enabled; this example is not available." << std::endl;
		std::cerr << std::endl;
		return -10;
	#else
		// Initialize winsock
		WSADATA wsData;
		WORD ver = MAKEWORD(2, 2);

		int wsOk = WSAStartup(ver, &wsData);
		if (wsOk != 0)
		{
			std::cerr << "Can't initialize winsock! Quitting" << std::endl;
			return -1;
		}

		// Create a socket
		SOCKET listening = socket(AF_INET, SOCK_STREAM, 0);
		if (listening == INVALID_SOCKET)
		{
			std::cerr << "Can't create a socket! Quitting" << std::endl;
			return -2;
		}

		// Bind the ip address and port to a socket
		sockaddr_in hint;
		hint.sin_family = AF_INET;
		hint.sin_port = htons(54000);
		hint.sin_addr.S_un.S_addr = INADDR_ANY;

		bind(listening, (sockaddr*)&hint, sizeof(hint));

		// Tell winsock the socket is for listening
		listen(listening, SOMAXCONN);

		// Wait for a connection
		sockaddr_in client;
		int clientSize = sizeof(client);

		SOCKET clientSocket = accept(listening, (sockaddr*)&client, &clientSize);

		char host[NI_MAXHOST];
		char service[NI_MAXHOST];

		ZeroMemory(host, NI_MAXHOST);
		ZeroMemory(service, NI_MAXHOST);

		if (getnameinfo((sockaddr*)&client, sizeof(client), host, NI_MAXHOST, service, NI_MAXSERV, 0) == 0)
		{
			std::cout << host << " connected on port " << service << std::endl;
		}
		else
		{
			inet_ntop(AF_INET, &client.sin_addr, host, NI_MAXHOST);
			std::cout << host << " connected on port " << ntohs(client.sin_port) << std::endl;
		}

		// Close listening socket
		closesocket(listening);


		// While loop: accept and echo message back to client
		char buf[SIZE_BUFFER];


		std::stringstream parms_stream;
		std::stringstream pk_stream;


		// We create the seal context that will be sent to the client
		EncryptionParameters parms(scheme_type::CKKS);
		size_t poly_modulus_degree = 8192;
		parms.set_poly_modulus_degree(poly_modulus_degree);
		parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 50, 20, 50 }));
		auto context = SEALContext::Create(parms);
		auto size = parms.save(parms_stream);
		
		
		int bytesReceived = 0;

		// We send the SEAL context to the client
		int bytesSent = send(clientSocket, parms_stream.str().c_str(), parms_stream.str().length() , 0);
		std::cout << "SEAL context sent to the client, bytes sent : " << bytesSent << std::endl;

		// We receive the public key from the client and register it
		do
		{
			ZeroMemory(buf, SIZE_BUFFER);
			bytesReceived = recv(clientSocket, buf, SIZE_BUFFER, 0);
			pk_stream << std::string(buf, bytesReceived);
			std::cout << bytesReceived << std::endl;
		} while (bytesReceived == SIZE_BUFFER);
		std::cout << "Public key successfully received from client" << std::endl;


		std::vector <Ciphertext> all_age_encrypted;
		Ciphertext encrypted;

		// We receive the data from the client and register it
		bool allDataRetrieved = false;
		while (!allDataRetrieved)
		{
			std::stringstream data_stream;
			do
			{

				ZeroMemory(buf, SIZE_BUFFER);
				bytesReceived = recv(clientSocket, buf, SIZE_BUFFER, 0);
				if (std::string(buf, bytesReceived) != STOP_MSG)
				{
					if (std::string(buf, bytesReceived) != END_BUFFER)
					{
						data_stream << std::string(buf, bytesReceived);
					}
				}
				else
				{
					allDataRetrieved = true;
				}
			} while (bytesReceived == SIZE_BUFFER);
			bytesSent = send(clientSocket, STOP_MSG, (unsigned)strlen(STOP_MSG), 0);
			if (!allDataRetrieved)
			{
				encrypted.load(context, data_stream);
				all_age_encrypted.push_back(encrypted);
			}
		}



		std::cout << "Data successfully received from client" << std::endl;
		
		
		
		// We load the encrypted values
		// Do operations over those values
		// And save it
		std::stringstream data_stream;
		Evaluator evaluator(context);
		Ciphertext age_encrypted_sum;
		evaluator.add_many(all_age_encrypted, age_encrypted_sum);

		auto size_encrypted_prod = age_encrypted_sum.save(data_stream);

		// We send the result of the encrypted product 
		bytesSent = send(clientSocket, data_stream.str().c_str(), data_stream.str().length(), 0);
		std::cout << "Sum encrypted sent to the client, bytes sent : " << bytesSent << std::endl;

		
		

		// Close the socket
		closesocket(clientSocket);

		// Cleanup winsock
		WSACleanup();


		return 0;
	#endif

}