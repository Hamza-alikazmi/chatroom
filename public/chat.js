const socket = io();

const input = document.getElementById("msg");
const messagesContainer = document.getElementById("messages");
const bottomAnchor = document.getElementById("bottom-anchor");

// Send message
function sendMessage() {
  const message = input.value.trim();
  if (!message) return;

  socket.emit("sendMessage", { username, message });
  input.value = "";
}

// Receive new message
socket.on("newMessage", (msg) => {
  const div = document.createElement("div");
  div.className = `flex items-end space-x-3 group ${msg.username === username ? "flex-row-reverse space-x-reverse" : ""}`;

  div.innerHTML = `
    <div class="flex-shrink-0">
      <div class="w-10 h-10 rounded-full bg-gradient-to-br from-primary to-primary-dark flex items-center justify-center text-white font-bold text-sm shadow-lg">
        ${msg.username.charAt(0).toUpperCase()}
      </div>
    </div>
    <div class="max-w-xs lg:max-w-md ${msg.username === username ? 'items-end' : 'items-start'}">
      <div class="px-4 py-3 rounded-2xl shadow-md ${msg.username === username 
        ? 'bg-primary text-white rounded-br-none' 
        : 'bg-white text-gray-800 border border-gray-200 rounded-bl-none'}">
        ${msg.username !== username ? `<p class="text-xs font-semibold opacity-80 mb-1">${msg.username}</p>` : ""}
        <p class="text-sm leading-relaxed">${msg.message}</p>
        <p class="text-xs mt-1 ${msg.username === username ? 'text-indigo-100' : 'text-gray-500'}">
          ${new Date(msg.timestamp || Date.now()).toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'})}
        </p>
      </div>
    </div>
  `;

  messagesContainer.insertBefore(div, bottomAnchor);
  bottomAnchor.scrollIntoView({ behavior: 'smooth' });
});

// Enter key sends message
input.addEventListener("keypress", function(e){
  if(e.key === "Enter" && !e.shiftKey){
    e.preventDefault();
    sendMessage();
  }
});
