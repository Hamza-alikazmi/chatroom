const socket = io();

function sendMessage() {
    const message = document.getElementById("msg").value.trim();
    if (!message) return;
    socket.emit("sendMessage", { username, message });
    document.getElementById("msg").value = "";
}

socket.on("newMessage", (msg) => {
    const messagesDiv = document.getElementById("messages");
    const p = document.createElement("p");
    p.innerHTML = `<b>${msg.username}:</b> ${msg.message}`;
    messagesDiv.appendChild(p);
    messagesDiv.scrollTop = messagesDiv.scrollHeight;
});

