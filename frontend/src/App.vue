<script setup>
import { ref, nextTick, watch, onMounted } from 'vue'
import { marked } from 'marked'
import DOMPurify from 'dompurify'

const userInput = ref('')
const isLoading = ref(false)
const sessionId = ref('')
// 新增一個狀態，用來記錄目前是否正在等待人工審核
const pendingApproval = ref(null)

const WELCOME_MESSAGE = { 
  role: 'assistant', 
  content: '🤖 **AI Threat Hunter** 已上線。\n\n我可以協助您：\n- 查詢 IP 威脅情資與真實地理位置\n- 檢索內部資安 SOP\n- 執行防火牆 IP 封鎖 (需人工授權)\n\n請輸入指令 (例如: `分析 IP 1.2.3.4 的風險`)' 
}
const messages = ref([{ ...WELCOME_MESSAGE }])

onMounted(() => {
  generateNewSession()
})

const generateNewSession = () => {
  sessionId.value = crypto.randomUUID ? crypto.randomUUID() : Math.random().toString(36).substring(2)
  messages.value = [{ ...WELCOME_MESSAGE }]
  pendingApproval.value = null // 切換對話時重置審批狀態
}

const renderMarkdown = (text) => {
  const rawHtml = marked.parse(text)
  return DOMPurify.sanitize(rawHtml)
}
const chatContainer = ref(null) 

const quickPrompts = [
  "查詢公司的 IP 封鎖 SOP",
  "分析 IP 1.2.3.4 的風險",
  "立刻封鎖 1.2.3.4"
]

watch(messages, async () => {
  await nextTick()
  if (chatContainer.value) {
    chatContainer.value.scrollTop = chatContainer.value.scrollHeight
  }
}, { deep: true })

const usePrompt = (prompt) => {
  if(pendingApproval.value) return // 審核中禁止快速提問
  userInput.value = prompt
  sendMessage()
}

// 處理主要的 Chat API 回應
const sendMessage = async () => {
  const text = userInput.value.trim()
  if (!text || isLoading.value || pendingApproval.value) return

  messages.value.push({ role: 'user', content: text })
  userInput.value = ''
  isLoading.value = true

  try {
    const response = await fetch('http://localhost:8080/api/chat', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message: text, session_id: sessionId.value })
    })

    const data = await response.json()

    // 判斷後端傳來的狀態
    if (data.status === 'requires_approval') {
      // 決定封鎖，觸發 HITL 中斷
      messages.value.push({ role: 'assistant', content: data.reply })
      pendingApproval.value = { ip: data.ip, reason: data.reason }
    } else if (data.status === 'success') {
      messages.value.push({ role: 'assistant', content: data.reply })
    } else {
      messages.value.push({ role: 'assistant', content: `❌ **發生錯誤:**\n ${data.message}` })
    }
  } catch (error) {
    messages.value.push({ role: 'assistant', content: '❌ **無法連線至伺服器**' })
  } finally {
    isLoading.value = false
  }
}

// 新增呼叫 Approve API 的功能
const submitApproval = async (approved) => {
  const currentApproval = pendingApproval.value;
  pendingApproval.value = null; // 隱藏審核面板
  isLoading.value = true;

  // 在畫面上印出使用者的決策
  const decisionText = approved ? `[系統指令] 授權同意封鎖 IP: ${currentApproval.ip}` : `[系統指令] 拒絕封鎖，取消操作。`
  messages.value.push({ role: 'user', content: decisionText, isSystemNode: true })

  try {
    const response = await fetch('http://localhost:8080/api/approve', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ 
        session_id: sessionId.value,
        approved: approved 
      })
    })

    const data = await response.json()
    if (data.status === 'success') {
      messages.value.push({ role: 'assistant', content: data.reply })
    }
  } catch (error) {
    messages.value.push({ role: 'assistant', content: '❌ **連線錯誤**' })
  } finally {
    isLoading.value = false
  }
}

// --- 黑名單狀態管理 ---
const blacklist = ref([])

// 取得黑名單
const fetchBlacklist = async () => {
  try {
    const res = await fetch('http://localhost:8080/api/blacklist')
    blacklist.value = await res.json()
  } catch (error) {
    console.error("無法獲取黑名單:", error)
  }
}

// 解除封鎖 IP
const unblockIp = async (ip) => {
  if(!confirm(`確定要解除封鎖 ${ip} 嗎？`)) return;
  
  try {
    await fetch(`http://localhost:8080/api/blacklist/${ip}`, {
      method: 'DELETE'
    })
    // 刪除成功後，重新拉取最新名單來更新畫面
    fetchBlacklist()
  } catch (error) {
    console.error("解鎖失敗:", error)
  }
}

// 網頁載入時自動抓取一次黑名單
onMounted(() => {
  fetchBlacklist()
})

</script>

<template>
  <div class="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950 text-gray-100 flex justify-center py-8 px-4 font-sans tracking-wide gap-6">
    
    <div class="w-full max-w-4xl bg-slate-800/50 backdrop-blur-md rounded-2xl shadow-2xl border border-slate-700/50 overflow-hidden flex flex-col h-[85vh] relative">
      
      <div class="bg-slate-900/80 px-6 py-4 flex items-center justify-between border-b border-slate-700/50">
        <div class="flex items-center gap-3">
          <div>
            <h1 class="text-lg font-bold bg-gradient-to-r from-blue-400 to-cyan-400 bg-clip-text text-transparent">AI Threat Hunter</h1>
            <p class="text-xs text-slate-400">Session: {{ sessionId.substring(0, 8) }}...</p>
          </div>
        </div>
        <div class="flex gap-3 items-center">
          <button @click="generateNewSession" class="text-xs hover:bg-slate-700 text-slate-300 px-3 py-1.5 rounded-full border border-slate-600 transition-colors">
            新對話
          </button>
        </div>
      </div>

      <div ref="chatContainer" class="flex-1 overflow-y-auto p-6 space-y-6 scroll-smooth relative">
        <div v-for="(msg, index) in messages" :key="index" :class="['flex', msg.role === 'user' ? 'justify-end' : 'justify-start']">
          <div class="flex max-w-[85%] gap-3" :class="msg.role === 'user' ? 'flex-row-reverse' : 'flex-row'">
            
            <div class="flex-shrink-0 mt-1">
              <div v-if="msg.role === 'assistant'" class="w-8 h-8 rounded-full bg-slate-700 flex items-center justify-center border border-slate-600 shadow-sm">🤖</div>
              <div v-else-if="msg.isSystemNode" class="w-8 h-8 rounded-full bg-orange-600 flex items-center justify-center shadow-sm">⚡</div>
              <div v-else class="w-8 h-8 rounded-full bg-blue-600 flex items-center justify-center shadow-sm">👤</div>
            </div>

            <div :class="[
                'px-5 py-3.5 rounded-2xl shadow-sm',
                msg.role === 'user' 
                  ? (msg.isSystemNode ? 'bg-orange-600/20 border border-orange-500/50 text-orange-200 rounded-tr-sm' : 'bg-blue-600 text-white rounded-tr-sm')
                  : 'bg-slate-800 border border-slate-700 text-slate-200 rounded-tl-sm'
              ]">
              <div v-if="msg.role === 'assistant'" class="prose prose-invert prose-sm max-w-none" v-html="renderMarkdown(msg.content)"></div>
              <div v-else class="whitespace-pre-wrap text-sm leading-relaxed">{{ msg.content }}</div>
            </div>
          </div>
        </div>

        <div v-if="isLoading" class="flex justify-start gap-3">
          <div class="flex-shrink-0 mt-1"><div class="w-8 h-8 rounded-full bg-slate-700 flex items-center justify-center border border-slate-600">🤖</div></div>
          <div class="bg-slate-800 border border-slate-700 rounded-2xl rounded-tl-sm px-5 py-4 text-slate-400 flex items-center gap-3">
            <span class="text-sm">Agent 處理中</span>
            <span class="flex gap-1.5 mt-1">
              <span class="w-1.5 h-1.5 bg-blue-500 rounded-full animate-bounce"></span>
              <span class="w-1.5 h-1.5 bg-blue-500 rounded-full animate-bounce" style="animation-delay: 0.15s"></span>
              <span class="w-1.5 h-1.5 bg-blue-500 rounded-full animate-bounce" style="animation-delay: 0.3s"></span>
            </span>
          </div>
        </div>
        
        <div :class="pendingApproval ? 'h-40' : 'h-4'" class="w-full shrink-0 transition-all duration-300"></div>
      </div>
      
      <div v-if="pendingApproval" class="absolute bottom-[90px] left-0 right-0 px-6 z-10 animate-fade-in-up">
        <div class="bg-slate-800 border-2 border-red-500/50 shadow-2xl shadow-red-900/20 rounded-xl p-4 flex flex-col gap-3">
          <div class="flex items-center gap-2 text-red-400">
            <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" viewBox="0 0 20 20" fill="currentColor">
              <path fill-rule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clip-rule="evenodd" />
            </svg>
            <span class="font-bold text-sm">等待分析師授權指令</span>
          </div>
          <div class="flex gap-3">
            <button @click="submitApproval(true)" class="flex-1 bg-red-600 hover:bg-red-500 text-white font-medium py-2.5 rounded-lg transition-colors flex items-center justify-center gap-2 text-sm shadow-lg">
              <span>🚨</span> 授權封鎖 {{ pendingApproval.ip }}
            </button>
            <button @click="submitApproval(false)" class="flex-1 bg-slate-700 hover:bg-slate-600 text-white font-medium py-2.5 rounded-lg border border-slate-600 transition-colors flex items-center justify-center gap-2 text-sm">
              <span>❌</span> 拒絕並觀察
            </button>
          </div>
        </div>
      </div>

      <div class="p-5 bg-slate-800/80 border-t border-slate-700/50 flex flex-col gap-3 z-20 relative">
        <div class="flex flex-wrap gap-2" v-if="messages.length === 1">
          <button v-for="prompt in quickPrompts" :key="prompt" @click="usePrompt(prompt)" :disabled="isLoading || pendingApproval" class="text-xs bg-slate-700/50 hover:bg-blue-600/30 text-slate-300 hover:text-blue-300 px-3 py-1.5 rounded-full border border-slate-600/50 transition-colors disabled:opacity-50">✨ {{ prompt }}</button>
        </div>

        <div class="relative flex items-center">
          <input 
            v-model="userInput" 
            @keyup.enter="sendMessage"
            type="text" 
            :placeholder="pendingApproval ? '系統已鎖定，請先回應上方審批面板...' : '輸入目標 IP 或資安疑問...'" 
            class="w-full bg-slate-900 text-slate-100 rounded-full pl-6 pr-16 py-4 focus:outline-none focus:ring-2 focus:ring-blue-500 border border-slate-700 shadow-inner disabled:opacity-50 transition-all text-sm"
            :disabled="isLoading || !!pendingApproval"
          />
          <button @click="sendMessage" :disabled="isLoading || !userInput.trim() || !!pendingApproval" class="absolute right-2 bg-blue-600 hover:bg-blue-500 text-white w-10 h-10 rounded-full flex items-center justify-center disabled:opacity-50 shadow-md">
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" class="w-5 h-5 ml-1"><path d="M3.478 2.404a.75.75 0 0 0-.926.941l2.432 7.905H13.5a.75.75 0 0 1 0 1.5H4.984l-2.432 7.905a.75.75 0 0 0 .926.94 60.519 60.519 0 0 0 18.445-8.986.75.75 0 0 0 0-1.218A60.517 60.517 0 0 0 3.478 2.404Z" /></svg>
          </button>
        </div>
      </div>
    </div>

    <div class="w-80 bg-slate-800/50 backdrop-blur-md rounded-2xl shadow-2xl border border-slate-700/50 flex flex-col p-4 h-[85vh] hidden lg:flex">
      
      <div class="flex items-center justify-between mb-4 pb-4 border-b border-slate-700">
        <h2 class="font-bold text-lg text-slate-100 flex items-center gap-2">
          <span></span> 防火牆黑名單
        </h2>
        <span class="bg-red-500/20 text-red-400 text-xs px-2 py-1 rounded-full font-bold">
          {{ blacklist.length }} 個 IP
        </span>
      </div>

      <div class="flex-1 overflow-y-auto space-y-3 pr-2 custom-scrollbar">
        
        <div v-if="blacklist.length === 0" class="text-center text-slate-500 text-sm py-10">
          目前無封鎖紀錄
        </div>

        <div v-for="item in blacklist" :key="item.ip" 
             class="bg-slate-900/50 border border-slate-700 rounded-lg p-3 shadow-sm hover:border-slate-500 transition-colors group">
          <div class="flex justify-between items-start mb-2">
            <div class="font-mono font-bold text-red-400 text-sm">{{ item.ip }}</div>
            <button @click="unblockIp(item.ip)" 
                    class="text-slate-500 hover:text-emerald-400 opacity-0 group-hover:opacity-100 transition-all"
                    title="解除封鎖">
              <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" viewBox="0 0 20 20" fill="currentColor">
                <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd" />
              </svg>
            </button>
          </div>
          <div class="text-xs text-slate-400 mb-1 line-clamp-2" :title="item.reason">
            原因: {{ item.reason }}
          </div>
          <div class="text-[10px] text-slate-500 font-mono">
            {{ item.timestamp }}
          </div>
        </div>

      </div>
    </div> </div>
</template>

<style>
.animate-fade-in-up {
  animation: fadeInUp 0.3s ease-out forwards;
}
@keyframes fadeInUp {
  from { opacity: 0; transform: translateY(10px); }
  to { opacity: 1; transform: translateY(0); }
}
</style>