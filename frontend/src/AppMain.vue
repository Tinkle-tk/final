<script setup>
import { reactive, ref } from 'vue'
import {
  crawlAdvisories,
  ingestDocument,
  ingestFromFile,
  ingestFromUrl,
  queryPatches,
  queryVulnerabilities,
} from './api'

function createBaseForm() {
  return {
    vendor: '',
    series: '',
    model: '',
    upgrade_path: '',
    extractor_mode: 'hybrid',
  }
}

function buildHints(form) {
  return {
    vendor: form.vendor || undefined,
    series: form.series || undefined,
    model: form.model || undefined,
    upgrade_path: form.upgrade_path || undefined,
  }
}

function formatSummary(data, prefix) {
  return `${prefix}: 识别 ${data.records} 条，新增 ${data.inserted} 条，更新 ${data.updated} 条，模式 ${data.extractor_mode}`
}

const queryForm = reactive({
  cve_id: '',
  product_name: '',
  vendor: '',
})

const textForm = reactive({
  ...createBaseForm(),
  text: '',
})

const urlForm = reactive({
  ...createBaseForm(),
  url: '',
})

const crawlForm = reactive({
  ...createBaseForm(),
  url: '',
  max_depth: 1,
  max_pages: 10,
})

const loading = ref(false)
const textLoading = ref(false)
const urlLoading = ref(false)
const fileLoading = ref(false)
const crawlLoading = ref(false)
const patchLoading = ref(false)

const vulnerabilities = ref([])
const patches = ref([])
const currentPatchCve = ref('')
const crawlDocuments = ref([])
const selectedFile = ref(null)
const globalError = ref('')
const notices = reactive({
  text: '',
  url: '',
  file: '',
  crawl: '',
})

function clearFeedback() {
  globalError.value = ''
}

async function onSearch() {
  loading.value = true
  clearFeedback()
  try {
    const { data } = await queryVulnerabilities(queryForm)
    vulnerabilities.value = data
  } catch (error) {
    globalError.value = error?.response?.data?.error || '查询失败，请检查后端服务是否已启动。'
  } finally {
    loading.value = false
  }
}

async function onQueryPatches(cveId) {
  patchLoading.value = true
  clearFeedback()
  try {
    const { data } = await queryPatches(cveId)
    currentPatchCve.value = data.cve_id
    patches.value = data.patches || []
  } catch (error) {
    globalError.value = error?.response?.data?.error || '补丁查询失败。'
  } finally {
    patchLoading.value = false
  }
}

async function onTextIngest() {
  textLoading.value = true
  notices.text = ''
  clearFeedback()
  try {
    const { data } = await ingestDocument({
      text: textForm.text,
      extractor_mode: textForm.extractor_mode,
      hints: buildHints(textForm),
    })
    notices.text = formatSummary(data, '文本导入完成')
  } catch (error) {
    globalError.value = error?.response?.data?.error || '文本导入失败。'
  } finally {
    textLoading.value = false
  }
}

async function onUrlIngest() {
  urlLoading.value = true
  notices.url = ''
  clearFeedback()
  try {
    const { data } = await ingestFromUrl({
      url: urlForm.url,
      extractor_mode: urlForm.extractor_mode,
      hints: buildHints(urlForm),
    })
    notices.url = `${formatSummary(data, 'URL 导入完成')}，来源 ${data.source_url || urlForm.url}`
  } catch (error) {
    globalError.value = error?.response?.data?.error || 'URL 导入失败。'
  } finally {
    urlLoading.value = false
  }
}

function onFileChange(event) {
  selectedFile.value = event.target.files?.[0] || null
}

async function onFileIngest() {
  clearFeedback()
  if (!selectedFile.value) {
    globalError.value = '请先选择一个 PDF、HTML 或 TXT 文件。'
    return
  }

  fileLoading.value = true
  notices.file = ''
  try {
    const formData = new FormData()
    formData.append('file', selectedFile.value)
    formData.append('extractor_mode', textForm.extractor_mode)

    for (const [key, value] of Object.entries(buildHints(textForm))) {
      if (value) {
        formData.append(key, value)
      }
    }

    const { data } = await ingestFromFile(formData)
    notices.file = `${formatSummary(data, '文件导入完成')}，文件 ${data.filename}`
  } catch (error) {
    globalError.value = error?.response?.data?.error || '文件导入失败。'
  } finally {
    fileLoading.value = false
  }
}

async function onCrawl() {
  crawlLoading.value = true
  notices.crawl = ''
  crawlDocuments.value = []
  clearFeedback()
  try {
    const { data } = await crawlAdvisories({
      url: crawlForm.url,
      extractor_mode: crawlForm.extractor_mode,
      hints: buildHints(crawlForm),
      max_depth: crawlForm.max_depth,
      max_pages: crawlForm.max_pages,
    })
    crawlDocuments.value = data.documents || []
    notices.crawl = `爬取完成: 扫描 ${data.pages_crawled} 个页面，成功处理 ${data.documents_processed} 个文档，识别 ${data.records} 条漏洞。`
  } catch (error) {
    globalError.value = error?.response?.data?.error || '站点爬取失败。'
  } finally {
    crawlLoading.value = false
  }
}
</script>

<template>
  <h1>工控设备固件漏洞知识库</h1>
  <p class="lead">支持文本导入、网页地址导入、PDF 文件上传，以及站内公告爬取后自动入库。</p>

  <section class="card">
    <h2>漏洞查询</h2>
    <div class="grid">
      <label>
        CVE 编号
        <input v-model="queryForm.cve_id" placeholder="例如 CVE-2024-12345" />
      </label>
      <label>
        产品型号
        <input v-model="queryForm.product_name" placeholder="例如 S7-1200" />
      </label>
      <label>
        厂商
        <input v-model="queryForm.vendor" placeholder="例如 Siemens" />
      </label>
    </div>
    <div class="actions">
      <button :disabled="loading" @click="onSearch">{{ loading ? '查询中...' : '查询漏洞' }}</button>
    </div>
  </section>

  <section class="card">
    <h2>文本导入</h2>
    <label>
      文本内容
      <textarea v-model="textForm.text" placeholder="粘贴网页正文、PDF 提取文本或公告文本"></textarea>
    </label>
    <div class="grid">
      <label>
        抽取模式
        <select v-model="textForm.extractor_mode">
          <option value="hybrid">hybrid（推荐）</option>
          <option value="llm">llm</option>
          <option value="rule">rule</option>
          <option value="auto">auto</option>
        </select>
      </label>
      <label>
        厂商
        <input v-model="textForm.vendor" />
      </label>
      <label>
        产品系列
        <input v-model="textForm.series" />
      </label>
      <label>
        产品型号
        <input v-model="textForm.model" />
      </label>
      <label>
        升级路径
        <input v-model="textForm.upgrade_path" />
      </label>
    </div>
    <div class="actions">
      <button :disabled="textLoading" @click="onTextIngest">{{ textLoading ? '导入中...' : '提交文本' }}</button>
      <span v-if="notices.text" class="badge">{{ notices.text }}</span>
    </div>
  </section>

  <section class="card">
    <h2>网页地址导入</h2>
    <div class="grid">
      <label class="full-span">
        网页或 PDF 地址
        <input v-model="urlForm.url" placeholder="例如 https://vendor.example.com/advisory.html" />
      </label>
      <label>
        抽取模式
        <select v-model="urlForm.extractor_mode">
          <option value="hybrid">hybrid（推荐）</option>
          <option value="llm">llm</option>
          <option value="rule">rule</option>
          <option value="auto">auto</option>
        </select>
      </label>
      <label>
        厂商
        <input v-model="urlForm.vendor" />
      </label>
      <label>
        产品系列
        <input v-model="urlForm.series" />
      </label>
      <label>
        产品型号
        <input v-model="urlForm.model" />
      </label>
      <label>
        升级路径
        <input v-model="urlForm.upgrade_path" />
      </label>
    </div>
    <div class="actions">
      <button :disabled="urlLoading" @click="onUrlIngest">{{ urlLoading ? '导入中...' : '抓取该地址并导入' }}</button>
      <span v-if="notices.url" class="badge">{{ notices.url }}</span>
    </div>
  </section>

  <section class="card">
    <h2>文件上传导入</h2>
    <div class="grid">
      <label class="full-span">
        选择文件
        <input type="file" accept=".pdf,.html,.htm,.txt" @change="onFileChange" />
      </label>
    </div>
    <div class="actions">
      <button :disabled="fileLoading" @click="onFileIngest">{{ fileLoading ? '上传中...' : '上传并导入文件' }}</button>
      <span v-if="selectedFile" class="hint">当前文件: {{ selectedFile.name }}</span>
      <span v-if="notices.file" class="badge">{{ notices.file }}</span>
    </div>
  </section>

  <section class="card">
    <h2>站点爬取导入</h2>
    <div class="grid">
      <label class="full-span">
        起始网址
        <input v-model="crawlForm.url" placeholder="例如 https://vendor.example.com/security" />
      </label>
      <label>
        抽取模式
        <select v-model="crawlForm.extractor_mode">
          <option value="hybrid">hybrid（推荐）</option>
          <option value="llm">llm</option>
          <option value="rule">rule</option>
          <option value="auto">auto</option>
        </select>
      </label>
      <label>
        最大深度
        <input v-model.number="crawlForm.max_depth" type="number" min="0" max="3" />
      </label>
      <label>
        最大页面数
        <input v-model.number="crawlForm.max_pages" type="number" min="1" max="30" />
      </label>
      <label>
        厂商
        <input v-model="crawlForm.vendor" />
      </label>
      <label>
        产品系列
        <input v-model="crawlForm.series" />
      </label>
      <label>
        产品型号
        <input v-model="crawlForm.model" />
      </label>
      <label>
        升级路径
        <input v-model="crawlForm.upgrade_path" />
      </label>
    </div>
    <div class="actions">
      <button :disabled="crawlLoading" @click="onCrawl">{{ crawlLoading ? '爬取中...' : '开始爬取并导入' }}</button>
      <span v-if="notices.crawl" class="badge">{{ notices.crawl }}</span>
    </div>
    <table v-if="crawlDocuments.length" class="mini-table">
      <thead>
        <tr>
          <th>页面</th>
          <th>状态</th>
          <th>识别条数</th>
          <th>新增</th>
          <th>更新</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="item in crawlDocuments" :key="`${item.url}-${item.depth}`">
          <td class="url-cell">{{ item.url }}</td>
          <td>{{ item.status }}</td>
          <td>{{ item.records ?? 0 }}</td>
          <td>{{ item.inserted ?? 0 }}</td>
          <td>{{ item.updated ?? 0 }}</td>
        </tr>
      </tbody>
    </table>
  </section>

  <section class="card">
    <h2>漏洞列表</h2>
    <table>
      <thead>
        <tr>
          <th>CVE</th>
          <th>类型</th>
          <th>CVSS</th>
          <th>披露日期</th>
          <th>来源</th>
          <th>描述</th>
          <th>操作</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="item in vulnerabilities" :key="item.cve_id">
          <td>{{ item.cve_id }}</td>
          <td>{{ item.vuln_type || '-' }}</td>
          <td>{{ item.cvss_score ?? '-' }}</td>
          <td>{{ item.disclosure_date || '-' }}</td>
          <td class="url-cell">{{ item.source_url || '-' }}</td>
          <td>{{ item.description }}</td>
          <td>
            <button :disabled="patchLoading" @click="onQueryPatches(item.cve_id)">
              {{ patchLoading ? '加载中...' : '查补丁' }}
            </button>
          </td>
        </tr>
      </tbody>
    </table>
  </section>

  <section class="card" v-if="currentPatchCve">
    <h2>补丁信息 - {{ currentPatchCve }}</h2>
    <table>
      <thead>
        <tr>
          <th>补丁编号</th>
          <th>升级路径</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="patch in patches" :key="patch.patch_id">
          <td>{{ patch.patch_id }}</td>
          <td>{{ patch.upgrade_path || '-' }}</td>
        </tr>
      </tbody>
    </table>
  </section>

  <p v-if="globalError" class="error">{{ globalError }}</p>
</template>
