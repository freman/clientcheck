# ClientCheck

Find out more about your clients - useful for when you're behind cloudflare or some other proxy/security system.

# Story

At work we were talking about ditching tls 1.1 but we had no idea who it would affect or how we could warn them about the change without a blanket broadcast. This would normally be a simple thing but we're behind cloudflare which doesn't make much information available to us.

I started writing a tool that we could cast into the ether and query with asynchronous javascript, and then I found [https://www.howsmyssl.com/](https://www.howsmyssl.com/).

# API

Make any call over https to this server and it'll return a JSON blob with everything it can find out about your client.

# Features

 * Returns as much information as I could get easily without forking the entire tls library
 * Can use standard ssl certificates and keys
 * Can use acme () certificates

# License

Copyright for portions of ClientCheck are held by Jeffrey M Hodges, 2013 as part of [https://www.howsmyssl.com/](https://www.howsmyssl.com/) and are provided under the MIT license.
Copyright for additional portions of Clientcheck are held by The Go Authors, 2009 as part of the Go language and are provided under the BSD license.
All other copyright for ClientCheck are held by Shannon Wynter, 2016.

This project is released under the MIT license, please see the included [LICENSE](LICENSE.md) file
