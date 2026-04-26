<script setup>
import { ref, nextTick, watch, onMounted, computed } from 'vue'
import { marked } from 'marked'
import DOMPurify from 'dompurify'

// ==========================================
// 1. 狀態變數 (State Management)
// ==========================================
const sessionId = ref('')
const isLoading = ref(false)
const userInput = ref('')
const messages = ref([])
const pendingApproval = ref(null)
const chatContainer = ref(null) 
const showSteps = ref({})
const blacklist = ref([])
const observations = ref([])

const WELCOME_MESSAGE = { 
  role: 'assistant', 
  content: `**AI Threat Hunter** 已連線

我是您的自動化資安應變助理。本系統整合了 Multi-Agent 協作架構與混合檢索 (Hybrid RAG) 知識庫，可為您執行以下任務：

1. 🌐 **動態威脅分析**：追蹤外部 IP 軌跡，並依據內部信譽庫進行風險評分 (Risk Scoring)
2. 🛡️ **防禦授權審批**：當風險評分達 **80 (Critical)** 或偵測到惡意意圖時，我將為您準備防火牆封鎖單 (Human-in-the-Loop)
3. 📚 **SOP 規範檢索**：可隨時向我查詢企業內部的資安標準作業程序與 SLA 等級

請問今天有什麼我可以協助您的？` 
}

const quickPrompts = [
  "High 等級事件的觸發條件？",
  "分析 IP 4.1.180.10 的風險",
  "封鎖 IP 1.8.255.64，原因為惡意掃描"
]

// ==========================================
// 2. 計算屬性 (Computed Properties)
// ==========================================
// 負責把「待審批」的 IP 卡片強制置頂顯示
const sortedObservations = computed(() => {
  if (!pendingApproval.value) return observations.value;

  const pendingIp = pendingApproval.value.ip;
  const target = observations.value.find(o => o.ip === pendingIp);
  
  if (target) {
    const others = observations.value.filter(o => o.ip !== pendingIp);
    return [target, ...others];
  }
  return observations.value;
});

// ==========================================
// 3. 生命週期與監聽 (Lifecycle & Watchers)
// ==========================================
onMounted(() => {
  generateNewSession()
  fetchAllLists() // 整合兩個 onMounted
})

// 監聽訊息變化 自動捲動到底部
watch(messages, async () => {
  await nextTick()
  if (chatContainer.value) {
    chatContainer.value.scrollTop = chatContainer.value.scrollHeight
  }
}, { deep: true })

// ==========================================
// 4. 對話與核心邏輯 (Chat & Session Methods)
// ==========================================
const generateNewSession = () => {
  sessionId.value = crypto.randomUUID ? crypto.randomUUID() : Math.random().toString(36).substring(2)
  messages.value = [{ ...WELCOME_MESSAGE }]
  pendingApproval.value = null
}

const renderMarkdown = (text) => {
  const rawHtml = marked.parse(text)
  return DOMPurify.sanitize(rawHtml)
}

const toggleSteps = (index) => {
  showSteps.value[index] = !showSteps.value[index]
}

const usePrompt = (prompt) => {
  if(pendingApproval.value) return
  userInput.value = prompt
  sendMessage()
}

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
    console.log("📦 收到後端資料:", data) 

    if (data.status === 'requires_approval') {
      messages.value.push({ 
        role: 'assistant', 
        content: data.reply || "⚠️ 警告：未提供回覆內容", 
        steps: data.steps || [] 
      })
      pendingApproval.value = { 
        ip: data.ip || '未知 IP', 
        reason: data.reason || '未提供原因' 
      }
    } else if (data.status === 'success') {
      messages.value.push({ 
        role: 'assistant', 
        content: data.reply || "完成。", 
        steps: data.steps || [] 
      })
    } else {
      messages.value.push({ role: 'assistant', content: `❌ **發生錯誤:**\n ${data.message}` })
    }
  } catch (error) {
    console.error("❌ 前端執行/渲染錯誤:", error)
    messages.value.push({ role: 'assistant', content: `❌ **前端錯誤:** ${error.message}` })
  } finally {
    isLoading.value = false
    fetchAllLists()
  }
}

// ==========================================
// 5. 審批流程 (Approval Workflow)
// ==========================================
const submitApproval = async (approved) => {
  const currentApproval = pendingApproval.value;
  pendingApproval.value = null;
  isLoading.value = true;

  const decisionText = approved ? `[系統指令] 授權同意封鎖 IP: ${currentApproval.ip}` : `[系統指令] 拒絕封鎖，繼續觀察。`
  messages.value.push({ role: 'user', content: decisionText, isSystemNode: true })

  try {
    const response = await fetch('http://localhost:8080/api/approve', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ session_id: sessionId.value, approved: approved })
    })

    const data = await response.json()
    if (data.status === 'success') {
      messages.value.push({ role: 'assistant', content: data.reply, steps: data.steps })
    }
  } catch (error) {
    messages.value.push({ role: 'assistant', content: '❌ **連線錯誤**' })
  } finally {
    isLoading.value = false
    fetchAllLists()
  }
}

// ==========================================
// 6. 清單與 API 管理 (List Management)
// ==========================================
const fetchAllLists = async () => {
  try {
    const [blRes, obRes] = await Promise.all([
      fetch('http://localhost:8080/api/blacklist'),
      fetch('http://localhost:8080/api/observations')
    ])
    blacklist.value = await blRes.json()
    observations.value = await obRes.json()
  } catch (error) {
    console.error("更新清單失敗:", error)
  }
}

const formatSource = (country, org) => {
  const isValid = (val) => val && val !== '未知' && val !== '/';
  const validCountry = isValid(country);
  const validOrg = isValid(org);
  
  if (validCountry && validOrg) return `${country} / ${org}`;
  if (validCountry) return country;
  if (validOrg) return org;
  return null; 
}

const unblockIp = async (ip) => {
  if(!confirm(`確定要解除封鎖 ${ip} 嗎？`)) return;
  try {
    await fetch(`http://localhost:8080/api/blacklist/${ip}`, { method: 'DELETE' })
    fetchAllLists()
  } catch (error) {
    console.error("解鎖失敗:", error)
  }
}
</script>

<template>
  <div class="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950 text-gray-100 flex justify-center py-8 px-4 font-sans tracking-wide gap-6">

    <div class="flex-1 max-w-3xl bg-slate-800/50 backdrop-blur-md rounded-2xl shadow-2xl border border-slate-700/50 overflow-hidden flex flex-col h-[85vh] relative">
      
      <div class="bg-slate-900/80 px-6 py-4 flex items-center justify-between border-b border-slate-700/50">
        <div class="flex items-center gap-3">
          <h1 class="text-lg font-bold bg-gradient-to-r from-blue-400 to-cyan-400 bg-clip-text text-transparent">AI Threat Hunter</h1>
          <span class="text-[10px] bg-blue-500/20 text-blue-400 px-2 py-0.5 rounded border border-blue-500/30">Dynamic Risk Engine v2</span>
        </div>
        <button @click="generateNewSession" class="text-xs hover:bg-slate-700 text-slate-300 px-3 py-1.5 rounded-full border border-slate-600 transition-colors">新對話</button>
      </div>

      <div ref="chatContainer" class="flex-1 overflow-y-auto p-6 space-y-6 scroll-smooth relative">
        <div v-for="(msg, index) in messages" :key="index" :class="['flex', msg.role === 'user' ? 'justify-end' : 'justify-start']">
          <div class="flex max-w-[90%] gap-3" :class="msg.role === 'user' ? 'flex-row-reverse' : 'flex-row'">
            
            <div class="flex-shrink-0 mt-1">
              <div v-if="msg.role === 'assistant'" class="w-8 h-8 rounded-full bg-slate-700 flex items-center justify-center border border-slate-600 shadow-sm">🤖</div>
              <div v-else-if="msg.isSystemNode" class="w-8 h-8 rounded-full bg-orange-600 flex items-center justify-center shadow-sm">⚡</div>
              <div v-else class="w-8 h-8 rounded-full bg-blue-600 flex items-center justify-center shadow-sm">👤</div>
            </div>

            <div class="flex flex-col gap-2 min-w-0" :class="msg.role === 'user' ? 'items-end' : 'items-start'">
              <div :class="[
                  'px-5 py-3.5 rounded-2xl shadow-sm w-fit',
                  msg.role === 'user' 
                    ? (msg.isSystemNode ? 'bg-orange-600/20 border border-orange-500/50 text-orange-200 rounded-tr-sm' : 'bg-blue-600 text-white rounded-tr-sm')
                    : 'bg-slate-800 border border-slate-700 text-slate-200 rounded-tl-sm'
                ]">
                <div v-if="msg.role === 'assistant'" class="prose prose-invert prose-sm max-w-none" v-html="renderMarkdown(msg.content)"></div>
                <div v-else class="whitespace-pre-wrap text-sm leading-relaxed">{{ msg.content }}</div>
              </div>

              <div v-if="msg.steps && msg.steps.length > 0" class="w-full max-w-md">
                <button @click="toggleSteps(index)" class="text-[10px] uppercase tracking-widest text-slate-500 hover:text-blue-400 transition-colors flex items-center gap-1.5 mb-1 px-1">
                  <span>{{ showSteps[index] ? '▼' : '▶' }}</span> Thought Process
                </button>
                <div v-show="showSteps[index]" class="bg-slate-900/50 rounded-lg border border-slate-700/50 p-3 space-y-3 mt-1 text-xs">
                  <div v-for="(step, sIdx) in msg.steps" :key="sIdx" class="flex gap-2">
                    <span v-if="step.type === 'thought'">🧠</span>
                    <span v-else-if="step.type === 'tool_output'">🔧</span>
                    <span v-else-if="step.type === 'reflection'">🔍</span>
                    <div class="flex-1">
                      <div class="font-bold text-slate-400">{{ step.type }}</div>
                      <div class="text-slate-500">{{ step.content }}</div>
                    </div>
                  </div>
                </div>
              </div>
            </div>

          </div>
        </div>
        
        <div v-if="isLoading" class="flex justify-start gap-3">
          <div class="w-8 h-8 rounded-full bg-slate-700 flex items-center justify-center border border-slate-600">🤖</div>
          <div class="bg-slate-800 border border-slate-700 rounded-2xl rounded-tl-sm px-5 py-4 text-slate-400 flex items-center gap-2">
            <span class="text-sm">Agent 分析中</span>
            <span class="flex gap-1 animate-pulse">...</span>
          </div>
        </div>
        <div :class="pendingApproval ? 'h-40' : 'h-4'"></div>
      </div>

      <div class="p-5 bg-slate-800/80 border-t border-slate-700/50 flex flex-col gap-3">
        <div class="flex flex-wrap gap-2" v-if="messages.length === 1">
          <button v-for="prompt in quickPrompts" :key="prompt" @click="usePrompt(prompt)" class="text-xs bg-slate-700/50 hover:bg-blue-600/30 text-slate-300 px-3 py-1.5 rounded-full border border-slate-600/50">✨ {{ prompt }}</button>
        </div>
        <div class="relative flex items-center">
          <input v-model="userInput" @keyup.enter="sendMessage" type="text" placeholder="分析 IP 或詢問資安規範..." class="w-full bg-slate-900 text-slate-100 rounded-full pl-6 pr-16 py-4 focus:outline-none focus:ring-2 focus:ring-blue-500 border border-slate-700 text-sm disabled:opacity-50" :disabled="isLoading || !!pendingApproval" />
          <button @click="sendMessage" class="absolute right-2 bg-blue-600 hover:bg-blue-500 text-white w-10 h-10 rounded-full flex items-center justify-center disabled:opacity-50" :disabled="isLoading || !userInput.trim() || !!pendingApproval">
            <svg class="w-5 h-5 ml-1" fill="currentColor" viewBox="0 0 24 24"><path d="M3.478 2.404a.75.75 0 0 0-.926.941l2.432 7.905H13.5a.75.75 0 0 1 0 1.5H4.984l-2.432 7.905a.75.75 0 0 0 .926.94 60.519 60.519 0 0 0 18.445-8.986.75.75 0 0 0 0-1.218A60.517 60.517 0 0 0 3.478 2.404Z" /></svg>
          </button>
        </div>
      </div>
    </div>

    <div class="w-80 flex flex-col gap-6 h-[85vh]">
      
      <div class="flex-1 bg-slate-800/50 backdrop-blur-md rounded-2xl shadow-xl border border-slate-700/50 flex flex-col p-4 overflow-hidden">
        <div class="flex items-center justify-between mb-4 border-b border-slate-700 pb-2">
          <h2 class="font-bold text-sm text-slate-200 flex items-center gap-2"><span></span> 風險觀察名單</h2>
          <span class="text-[10px] bg-slate-700 text-slate-300 px-2 py-0.5 rounded-full">{{ observations.length }} IPs</span>
        </div>
        
        <div class="flex-1 overflow-y-auto space-y-3 pr-1 custom-scrollbar">
          
          <div v-for="item in sortedObservations" :key="item.ip" 
               class="bg-slate-900/60 border border-slate-700 rounded-lg p-3 transition-all hover:border-slate-500 relative overflow-hidden group">
            
            <div class="absolute bottom-0 left-0 h-1 bg-slate-800 w-full">
               <div class="h-full transition-all duration-700 ease-out"
                    :class="{
                      'bg-red-500 shadow-[0_0_8px_rgba(239,68,68,0.8)]': item.score >= 80,
                      'bg-amber-500': item.score >= 40 && item.score < 80,
                      'bg-emerald-500': item.score < 40
                    }"
                    :style="{ width: `${item.score}%` }">
               </div>
            </div>

            <div class="flex justify-between items-center mb-2">
              <span class="font-mono font-bold text-xs text-slate-200">{{ item.ip }}</span>
              <span :class="['text-[10px] font-bold px-2 py-0.5 rounded-full border',
                    item.score >= 80 ? 'bg-red-500/20 text-red-400 border-red-500/50 animate-pulse' :
                    item.score >= 40 ? 'bg-amber-500/20 text-amber-400 border-amber-500/50' :
                    'bg-emerald-500/20 text-emerald-400 border-emerald-500/50']">
                {{ item.score }} pts
              </span>
            </div>
            
            <div class="text-[10px] text-slate-400 truncate mb-2 flex items-center gap-1.5">
              <span>🌐</span>
              <span v-if="formatSource(item.country, item.org)">
                {{ formatSource(item.country, item.org) }}
              </span>
              <span v-else class="text-slate-500 italic">未知來源 (Unknown)</span>
            </div>
            
            <div class="flex justify-between items-center text-[9px] text-slate-500 font-mono">
              <div class="flex items-center gap-2">
                <span>偵測 {{ item.hits }} 次</span>
                <span v-if="item.last_seen" title="最後偵測時間"> {{ item.last_seen.split(' ')[1] }}</span>
              </div>
              
              <span v-if="item.score >= 80" class="text-red-400/90 font-bold flex items-center gap-1">
                <span class="animate-ping absolute inline-flex h-2 w-2 rounded-full bg-red-400 opacity-75"></span>
                <span class="relative inline-flex rounded-full h-2 w-2 bg-red-500"></span>
                達標
              </span>
            </div>
          
            <div v-if="pendingApproval && pendingApproval.ip === item.ip" 
                 class="mt-3 pt-3 border-t border-red-500/30 flex flex-col gap-2">
                <div class="text-[10px] text-red-400 font-bold flex items-center justify-between">
                  <span class="flex items-center gap-1.5"><span class="animate-pulse">⚠️</span> 系統請求封鎖授權</span>
                </div>
                <div class="flex gap-2 mt-1">
                  <button @click="submitApproval(true)" class="flex-1 bg-red-600 hover:bg-red-500 text-white text-[11px] py-1.5 rounded shadow-sm transition-colors flex justify-center items-center gap-1">
                    執行封鎖
                  </button>
                  <button @click="submitApproval(false)" class="flex-1 bg-slate-700 hover:bg-slate-600 text-slate-200 border border-slate-600 text-[11px] py-1.5 rounded transition-colors flex justify-center items-center gap-1">
                    退回觀察
                  </button>
                </div>
            </div>
          </div> 
          
          <div v-if="observations.length === 0" class="text-center text-slate-600 text-xs py-10 flex flex-col items-center gap-2">
            <span class="text-2xl opacity-50"></span>
            目前無觀察對象
          </div>
          
        </div> 
      </div>   

      <div class="h-[40%] bg-slate-800/50 backdrop-blur-md rounded-2xl shadow-xl border border-red-500/20 flex flex-col p-4 overflow-hidden relative">
        <div class="absolute top-0 right-0 w-32 h-32 bg-red-500/5 rounded-full blur-3xl pointer-events-none"></div>

        <div class="flex items-center justify-between mb-4 border-b border-slate-700 pb-2">
          <h2 class="font-bold text-sm text-slate-200 flex items-center gap-2"><span></span> 防火牆黑名單</h2>
          <span class="text-[10px] bg-slate-700 text-slate-300 px-2 py-0.5 rounded-full">{{ blacklist.length }} IPs</span>
        </div>
        
        <div class="flex-1 overflow-y-auto space-y-2 pr-1 custom-scrollbar relative z-10">
          <div v-for="item in blacklist" :key="item.ip" 
               class="bg-slate-900/60 border border-slate-700/80 hover:border-red-500/50 rounded-lg p-2.5 flex flex-col gap-1.5 group transition-all">
            
            <div class="flex justify-between items-start">
              <div class="font-mono font-bold text-xs text-red-400">{{ item.ip }}</div>
              <button @click="unblockIp(item.ip)" class="text-slate-600 hover:text-emerald-400 opacity-0 group-hover:opacity-100 transition-all" title="解除封鎖">
                <svg class="h-4 w-4" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd" /></svg>
              </button>
            </div>
            
            <div class="text-[10px] text-slate-300 truncate" :title="item.reason">{{ item.reason }}</div>
            
            <div class="flex justify-between items-end mt-1">
               <div class="text-[9px] text-slate-500 flex items-center gap-1">
                 <span>🌐</span>
                 <span class="truncate max-w-[120px]">{{ (item.country && item.country !== '未知') ? item.country : 'Unknown' }}</span>
               </div>
               <div class="text-[9px] text-slate-600 font-mono">{{ item.timestamp ? item.timestamp.split(' ')[1] : '' }}</div>
            </div>
          </div>
          
          <div v-if="blacklist.length === 0" class="text-center text-slate-600 text-xs py-5">
            無封鎖紀錄
          </div>
        </div>
      </div>
    </div>
    
  </div>
</template>

<style>
.custom-scrollbar::-webkit-scrollbar { width: 4px; }
.custom-scrollbar::-webkit-scrollbar-thumb { background: #334155; border-radius: 10px; }
.prose { line-height: 1.6; }
</style>