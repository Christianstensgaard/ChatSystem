
Getting Started:

1. Run the `docker-compose up` command.
2. Go to [localhost](http://localhost:8080/).
3. Follow the guide below!

![alt text](/img/image-0.png)

It's important to first create the users who want to chat together.  
1. Create a username.  
2. Click "Register."

You are now linked to the web-socket, and the next step is to connect to the other person.

---

![alt text](/img/image-1.png)  
Since this is a simple application, you need to handle some tasks manually. This means both clients (e.g., Christian & Bente) need to connect to each other as shown in this image.

1. Type the other person's username and press "Tab" or click out. In the console, you should see a message indicating the key has been shared.  
2. Repeat this step for both clients before starting the chat.

---

![alt text](/img/image-2.png)  
Demonstration of the chat working in real time.

![alt text](/img/image-3.png)  
Console information on the server side.

# Notes  
I've tried many different approaches to get the system working, and you may find various elements in the code that I left for demonstration purposes.

The system runs an HTTP server written in C++ and a WebSocket in C++. The client side is implemented in JavaScript, which I'm not very familiar with, so there might be some less-than-ideal implementations.

The system uses end-to-end encryption, where the client generates the keys and returns the public key to the server. This key can then be used when others connect, ensuring secure communication. However, I did not implement functionality to store the chat history if the session is closed and reopened.

