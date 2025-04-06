
/*   @Planqx EDR -	Server side forwarder (HeartBeat-Core) this Code WHich initilize the initial connection :)
 *									@Author : Written By @Havox :)

 *    Permission is hereby granted, free of charge, to any person obtaining
 *    this piece of code, and you can deal in the Software without restriction,
 *    including without limitation the rights to use and modify and to permit
 *	  persons to whom the Software is furnished to do so,subject to the following
 *	  conditions:
 *
 *    The above copyright notice and this permission notice shall be included
 *    in all copies or substantial portions of the Software.
 *
 *    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 *    OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 *    MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 *    IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 *    CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 *    TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 *    SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */


#include <iostream>
#include <string>
#include "nlohmann/json.hpp"
 //#include <curlpp/cURLpp.hpp>
 //#include <curlpp/Easy.hpp>
 //#include <curlpp/Options.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio.hpp>
#include <nlohmann/json.hpp>
#include <memory>

#define _WIN32_WINNT 0x0601

using json = nlohmann::json;
namespace beast = boost::beast;
namespace http = beast::http;
namespace asio = boost::asio;
using tcp_stream = beast::tcp_stream;
using flat_buffer = beast::flat_buffer;
using tcp = asio::ip::tcp;

// session class to handle the client connection
// used enable_shared_from_this to share ownership of existing share_ptr

// Code for the session management >>>  Initial TCP stream session creation /& client conneciton
class sessions : public std::enable_shared_from_this<sessions> {

	// decelearibng the stream, buffer and request object within the shared memory
	// this will handle the client request concurrently
	tcp_stream stream_; // TCP connection
	flat_buffer buffer_; // Temp Storage
	beast::http::request<http::string_body> req_; // stored the response data

	// Testing Purpose "Leave IT:"

	//http::request<http::string_body> req_Test;  

public:
	sessions(tcp::socket&& socket) : stream_(std::move(socket)) {}
	void run() {
		do_read();
	}
private:
	void do_read() {
		// just reset the request object
		req_ = {};
		beast::http::async_read(stream_, buffer_, req_, beast::bind_front_handler(&sessions::on_read, shared_from_this()));
	}
	// Initial 
	void on_read(beast::error_code ec, std::size_t) {
		if (ec) {
			std::cerr << "Read Error: " << ec.message() << std::endl;
			return;
		}

		// Checking The request method "POST" and target endpoint
		if (req_.method() == http::verb::post && req_.target() == "/connect") {

			// Parse the Client connection status in JSON format
			json j = json::parse(req_.body());
			//priting the status of the connection from and conver the json "Status" into string
			std::cout << "HeartBeat Lived ==> Client Connected" << j["status"].get<std::string>() << std::endl;
			json json_response = { {"Status","connected"} };
			// dumping the client response JSON
			std::string response_body = json_response.dump();

			http::response<http::string_body> res{ http::status::ok,req_.version() };
			res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
			res.set(http::field::content_type, "application/json");
			res.body() = response_body;
			res.prepare_payload();

			// writing response from the client asynchronously 
			http::async_write(stream_, res,
				beast::bind_front_handler(&sessions::on_write, shared_from_this()));
		}
		// If connection between the server and client is not done it return error code and close the connection
		else {
			beast::error_code ec;
			stream_.socket().shutdown(tcp::socket::shutdown_send, ec);
		}
	}
	void on_write(beast::error_code ec, std::size_t) {
		if (!ec) {
			std::cout << "Response from HeartBeat 'Succeeded'" << std::endl;
		}
		// Close connection after response
		beast::error_code ec_;
		stream_.socket().shutdown(tcp::socket::shutdown_send, ec);
	}
};

// listner code for listen the client connections
class listener :public std::enable_shared_from_this<listener> {
	// using asynchronous input content from the client
	asio::io_context& ioc_;
	// accept the TCP conneciton from this client 
	tcp::acceptor acceptor_;

public:
	listener(asio::io_context& ioc, tcp::endpoint endpoint) : ioc_(ioc), acceptor_(ioc) {
		acceptor_.open(endpoint.protocol());
		acceptor_.set_option(asio::socket_base::reuse_address(true));
		acceptor_.bind(endpoint);
		acceptor_.listen();
	}
	void run() {
		do_accept();
	}

private:
	void do_accept() {
		// accept the connnection using the input from the client
		acceptor_.async_accept(asio::make_strand(ioc_),
			beast::bind_front_handler(&listener::on_accept , shared_from_this()));
	}
	void on_accept(beast::error_code ec, tcp::socket socket) {
		if (!ec) {
			// move to session to handle the client 
			std::make_shared<sessions>(std::move(socket))->run();
		}
		do_accept(); // accept the next connection
	}

};

int main() {

	try {
		asio::io_context ioc{12}; // Create io_context for event handling 
		auto const address = asio::ip::make_address("127.0.0.1");
		auto const port = static_cast<unsigned short>(31004);

		// passing the content if ioc, addredd, port to the listner to listen
		std::make_shared<listener>(ioc, tcp::endpoint{ address,port })->run();
		std::cout << "Waiting for HeartBeat to ping......" << std::endl;
		ioc.run();
		}
			catch (const std::exception e) {
			std::cerr << "Simply Error -> See what : " << e.what() << std::endl;
			return 1;
		}
		return 0;
	}