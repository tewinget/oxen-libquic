#include "btstream.hpp"

#include <stdexcept>

namespace oxen::quic
{

    static std::pair<std::ptrdiff_t, std::size_t> get_location(bstring& data, std::string_view substr)
    {
        auto* bsubstr = reinterpret_cast<const std::byte*>(substr.data());
        // Make sure the given substr actually is a substr of data:
        assert(bsubstr >= data.data() && bsubstr + substr.size() <= data.data() + data.size());
        return {bsubstr - data.data(), substr.size()};
    }

    message::message(BTRequestStream& bp, bstring req, bool is_timeout) :
            data{std::move(req)}, return_sender{bp.weak_from_this()}, _rid{bp.reference_id}, timed_out{is_timeout}
    {
        if (!is_timeout)
        {
            oxenc::bt_list_consumer btlc(data);

            req_type = get_location(data, btlc.consume_string_view());
            req_id = btlc.consume_integer<int64_t>();

            if (type() == TYPE_COMMAND)
                ep = get_location(data, btlc.consume_string_view());

            req_body = get_location(data, btlc.consume_string_view());

            btlc.finish();
        }
    }

    void message::respond(bstring_view body, bool error) const
    {
        log::trace(bp_cat, "{} called", __PRETTY_FUNCTION__);

        if (auto ptr = return_sender.lock())
            ptr->respond(req_id, body, error);
        else
            log::warning(bp_cat, "BTRequestStream unable to send response: stream has gone away");
    }

    void BTRequestStream::respond(int64_t rid, bstring_view body, bool error)
    {
        log::trace(bp_cat, "{} called", __PRETTY_FUNCTION__);

        send(sent_request{*this, encode_response(rid, body, error), rid}.payload());
    }

    void BTRequestStream::check_timeouts()
    {
        log::trace(bp_cat, "{} called", __PRETTY_FUNCTION__);
        return check_timeouts(get_time());
    }
    void BTRequestStream::check_timeouts(std::optional<std::chrono::steady_clock::time_point> now)
    {
        log::trace(bp_cat, "{} called", __PRETTY_FUNCTION__);

        while (!sent_reqs.empty())
        {
            auto& f = *sent_reqs.front();
            if (now && !f.is_expired(*now))
                return;
            auto ptr = std::move(sent_reqs.front());
            sent_reqs.pop_front();

            try
            {
                f.cb(std::move(f).to_timeout());
            }
            catch (const std::exception& e)
            {
                log::error(bp_cat, "Uncaught exception from timeout response handler: {}", e.what());
            }
        }
    }

    void BTRequestStream::receive(bstring_view data)
    {
        log::trace(bp_cat, "bparser recv data callback called!");

        if (is_closing())
            return;

        try
        {
            process_incoming(to_sv(data));
        }
        catch (const std::exception& e)
        {
            log::error(bp_cat, "Exception caught: {}", e.what());
            close(BPARSER_ERROR_EXCEPTION);
        }
    }

    void BTRequestStream::closed(uint64_t app_code)
    {
        log::debug(bp_cat, "bparser closed with {}", quic_strerror(app_code));

        // First time out any pending requests, even if they haven't hit the timer, because we're
        // being closed and so they can never be answered.
        check_timeouts(std::nullopt);

        if (close_callback)
        {
            try
            {
                close_callback(*this, app_code);
            }
            catch (const std::exception& e)
            {
                log::error(bp_cat, "Uncaught exception from bparser stream close callback: {}", e.what());
            }
        }
    }

    void BTRequestStream::register_handler(std::string ep, std::function<void(message)> func)
    {
        endpoint.call(
                [this, ep = std::move(ep), func = std::move(func)]() mutable { func_map[std::move(ep)] = std::move(func); });
    }

    void BTRequestStream::register_generic_handler(std::function<void(message)> request_handler)
    {
        log::debug(bp_cat, "Bparser set generic request handler");
        endpoint.call([this, func = std::move(request_handler)]() mutable { generic_handler = std::move(func); });
    }

    void BTRequestStream::handle_input(message msg)
    {
        log::trace(bp_cat, "{} called to handle {} input", __PRETTY_FUNCTION__, msg.type());

        log::info(bp_cat, "Received bt_encoded message:\n{}\n", msg.view());
        all_data += "MARKER";

        if (auto type = msg.type(); type == message::TYPE_REPLY || type == message::TYPE_ERROR)
        {
            log::trace(log_cat, "Looking for request with req_id={}", msg.req_id);
            // Iterate using forward iterators, s.t. we go highest (newest) rids to lowest (oldest) rids.
            // As a result, our comparator checks if the sent request ID is greater thanthan the target rid
            auto itr = std::lower_bound(
                    sent_reqs.begin(),
                    sent_reqs.end(),
                    msg.req_id,
                    [](const std::shared_ptr<sent_request>& sr, int64_t rid) { return sr->req_id < rid; });

            if (itr != sent_reqs.end())
            {
                log::debug(bp_cat, "Successfully matched response to sent request!");
                auto req = std::move(*itr);
                sent_reqs.erase(itr);
                try
                {
                    req->cb(std::move(msg));
                }
                catch (const std::exception& e)
                {
                    log::error(bp_cat, "Uncaught exception from response handler: {}", e.what());
                }
            }
            return;
        }

        // `msg` likely isn't valid in the exception handlers below, so extract what we need to
        // send a response anyway:
        const auto req_id = msg.req_id;
        const auto ep = msg.endpoint_str();
        try
        {
            if (!func_map.empty())
            {
                if (auto itr = func_map.find(ep); itr != func_map.end())
                {
                    log::debug(bp_cat, "Executing request endpoint {}", msg.endpoint());
                    return itr->second(std::move(msg));
                }
            }
            if (generic_handler)
            {
                log::debug(bp_cat, "Executing generic request handler for endpoint {}", msg.endpoint());
                return generic_handler(std::move(msg));
            }
            throw no_such_endpoint{};
        }
        catch (const no_such_endpoint&)
        {
            log::warning(bp_cat, "No handler found for endpoint {}, returning error response", ep);
            respond(req_id, convert_sv<std::byte, char>("Invalid endpoint '{}'"_format(ep)), true);
        }
        catch (const std::exception& e)
        {
            log::error(
                    bp_cat,
                    "Handler for {} threw an uncaught exception ({}); returning a generic error message",
                    ep,
                    e.what());
            respond(req_id, "An error occurred while processing the request"_bsv, true);
        }
    }

    void BTRequestStream::process_incoming(std::string_view req)
    {
        log::trace(bp_cat, "{} called", __PRETTY_FUNCTION__);

        all_data += req;
        while (not req.empty())
        {
            if (current_len == 0)
            {
                size_t consumed = 0;

                if (not size_buf.empty())
                {
                    size_t prev_len = size_buf.size();
                    size_buf += req.substr(0, MAX_REQ_LEN_ENCODED);

                    consumed = parse_length(size_buf);

                    if (consumed == 0)
                        return;

                    size_buf.clear();
                    req.remove_prefix(consumed - prev_len);
                }
                else
                {
                    consumed = parse_length(convert_sv<char>(req));
                    if (consumed == 0)
                    {
                        size_buf += req;
                        return;
                    }

                    req.remove_prefix(consumed);
                }
            }

            assert(current_len > 0);  // We shouldn't get out of the above without knowing this

            if (auto r_size = req.size() + buf.size(); r_size >= current_len)
            {
                // We have enough data for a complete request, so copy whatever we need to
                // complete the current request into buf and process it, leaving behind the
                // potential start of the next request:
                if (buf.size() < current_len)
                {
                    size_t need = current_len - buf.size();
                    buf += convert_sv<std::byte>(req.substr(0, need));
                    req.remove_prefix(need);
                }

                handle_input(message{*this, std::move(buf)});
                buf.clear();

                // Back to the top to try processing another request that might have arrived in
                // the same stream buffer
                current_len = 0;
                continue;
            }

            // Otherwise we don't have enough data on hand for a complete request, so move what we
            // got to the buffer to be processed when the next incoming chunk of data arrives.
            buf.reserve(current_len);
            buf += convert_sv<std::byte>(req);
            return;
        }
    }

    std::string BTRequestStream::encode_command(std::string_view endpoint, int64_t rid, bstring_view body)
    {
        oxenc::bt_list_producer btlp;

        btlp.append(message::TYPE_COMMAND);
        btlp.append(rid);
        btlp.append(endpoint);
        btlp.append(body);

        return std::move(btlp).str();
    }

    std::string BTRequestStream::encode_response(int64_t rid, bstring_view body, bool error)
    {
        oxenc::bt_list_producer btlp;

        btlp.append(error ? message::TYPE_ERROR : message::TYPE_REPLY);
        btlp.append(rid);
        btlp.append(body);

        auto foo = std::move(btlp).str();
        log::info(bp_cat, "Sending bt_encoded message:\n{}\n", foo);
        return std::move(foo);
    }

    /** Returns:
            0: length was incomplete
            >0: number of characters (including colon) parsed from front of req

        Error:
            throws on invalid value
    */
    size_t BTRequestStream::parse_length(std::string_view req)
    {
        auto pos = req.find_first_of(':');

        // request is incomplete with no readable request length
        if (pos == std::string_view::npos)
        {
            if (req.size() >= MAX_REQ_LEN_ENCODED)
                // we didn't find a valid length, but do have enough consumed for the maximum valid
                // length, so something is clearly wrong with this input.
                throw std::invalid_argument{"Invalid incoming request; invalid encoding or request too large"};

            return 0;
        }

        auto [ptr, ec] = std::from_chars(req.data(), req.data() + pos, current_len);

        const char* bad = nullptr;
        if (ec != std::errc() || ptr != req.data() + pos)
            bad = "Invalid incoming request encoding!";
        else if (current_len == 0)
            bad = "Invalid empty bt request!";
        else if (current_len > MAX_REQ_LEN)
            bad = "Request exceeds maximum size!";

        if (bad)
        {
            log::error(bp_cat, "All data ever: \"{}\"", all_data);
            close(BPARSER_ERROR_EXCEPTION);
            throw std::invalid_argument{bad};
        }

        return pos + 1;
    }

    size_t BTRequestStream::num_pending() const
    {
        return call_get_accessor(&BTRequestStream::num_pending_impl);
    }

}  // namespace oxen::quic
