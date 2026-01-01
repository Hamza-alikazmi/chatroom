// ===== Socket Connection =====
const socket = io({
  transports: ["websocket"],
  withCredentials: true
});

// ===== DOM Elements =====
const input = document.getElementById("msg");
const messagesContainer = document.getElementById("messages");
const bottomAnchor = document.getElementById("bottom-anchor");

// ===== Helpers =====
function escapeHTML(str) {
  return str.replace(/[&<>"']/g, (m) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;"
  })[m]);
}

function scrollToBottom() {
  bottomAnchor.scrollIntoView({ behavior: "smooth" });
}

// ===== Send Message =====
function sendMessage() {
  const message = input.value.trim();
  if (!message || !socket.connected) return;

  socket.emit("sendMessage", {
    username,
    message,
    timestamp: Date.now()
  });

  input.value = "";
}

// ===== Receive Message =====
socket.on("newMessage", (msg) => {
  const isMine = msg.username === username;

  const div = document.createElement("div");
  div.className = `flex items-end space-x-3 group ${
    isMine ? "flex-row-reverse space-x-reverse" : ""
  }`;

  div.innerHTML = `
    <div class="flex-shrink-0">
      <div class="w-10 h-10 rounded-full bg-gradient-to-br from-primary to-primary-dark flex items-center justify-center text-white font-bold text-sm shadow-lg">
        ${escapeHTML(msg.username.charAt(0).toUpperCase())}
      </div>
    </div>

    <div class="max-w-xs lg:max-w-md ${
      isMine ? "items-end" : "items-start"
    }">
      <div class="px-4 py-3 rounded-2xl shadow-md ${
        isMine
          ? "bg-primary text-white rounded-br-none"
          : "bg-white text-gray-800 border border-gray-200 rounded-bl-none"
      }">
        ${
          !isMine
            ? `<p class="text-xs font-semibold opacity-80 mb-1">${escapeHTML(
                msg.username
              )}</p>`
            : ""
        }

        <p class="text-sm leading-relaxed">
          ${escapeHTML(msg.message)}
        </p>

        <p class="text-xs mt-1 ${
          isMine ? "text-indigo-100" : "text-gray-500"
        }">
          ${new Date(msg.timestamp || Date.now()).toLocaleTimeString([], {
            hour: "2-digit",
            minute: "2-digit"
          })}
        </p>
      </div>
    </div>
  `;

  messagesContainer.insertBefore(div, bottomAnchor);
  scrollToBottom();
});

// ===== Enter / Shift+Enter Handling =====
input.addEventListener("keydown", (e) => {
  if (e.key === "Enter" && !e.shiftKey) {
    e.preventDefault();
    sendMessage();
  }
});

// ===== Socket Status =====
socket.on("connect", () => {
  console.log("🟢 Connected to chat server");
});

socket.on("disconnect", () => {
  console.log("🔴 Disconnected from chat server");
});
