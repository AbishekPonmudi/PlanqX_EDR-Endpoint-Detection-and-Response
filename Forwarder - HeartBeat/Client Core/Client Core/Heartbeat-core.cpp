
/*   @Planqx EDR -	Client side forwarder (HeartBeat) this Code WHich initilize the initial connection :)
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
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/asio.hpp>
#include "nlohmann/json.hpp"
#include <iostream>

using json = nlohmann::json;
namespace beast = boost::beast;
namespace http = beast::http;
namespace asio = boost::asio;
using tcp = asio::ip::tcp;

int main() {
    try {
        // Initialize IO context
        asio::io_context ioc;

        // Set up resolver and stream
        tcp::resolver resolver(ioc);
        beast::tcp_stream stream(ioc);

        // Resolve and connect to server
        auto const results = resolver.resolve("127.0.0.1", "31004");
        stream.connect(results);

        // Create JSON request payload
        json request_json = { {"status", "connected"} };
        std::string request_body = request_json.dump();

        // Prepare HTTP POST request
        http::request<http::string_body> req{ http::verb::post, "/connect", 11 };
        req.set(http::field::host, "127.0.0.1");
        req.set(http::field::content_type, "application/json");
        req.body() = request_body;
        req.prepare_payload();

        // Send the request
        http::write(stream, req);

        // Prepare to receive response
        beast::flat_buffer buffer;
        http::response<http::string_body> res;
        http::read(stream, buffer, res);

        // Parse and display JSON response
        json j = json::parse(res.body());
        std::cout << "Server says: " << j["status"].get<std::string>() << std::endl;

        // Cleanly close the connection
        stream.close();
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}