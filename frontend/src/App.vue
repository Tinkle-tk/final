<script setup>
import { reactive, ref } from 'vue'
import { ingestDocument, queryPatches, queryVulnerabilities } from './api'

const queryForm = reactive({
  cve_id: '',
  product_name: '',
  vendor: '',
})

const ingestForm = reactive({
  text: '',
  vendor: '',
  series: '',
  model: '',
  upgrade_path: '',
  extractor_mode: 'hybrid',
})

const loading = ref(false)
const ingesting = ref(false)
const patchLoading = ref(false)
const vulnerabilities = ref([])
const patches = ref([])
const currentPatchCve = ref('')
const message = ref('')
const error = ref('')

async function onSearch() {
  loading.value = true
  error.value = ''
  try {
    const { data } = await queryVulnerabilities(queryForm)
    vulnerabilities.value = data
  } catch (e) {
    error.value = e?.response?.data?.error || '查询失败，请检查后端服务是否启动。'
  } finally {
    loading.value = false
  }
}

async function onQueryPatches(cveId) {
  patchLoading.value = true
  error.value = ''
  try {
    const { data } = await queryPatches(cveId)
    currentPatchCve.value = data.cve_id
    patches.value = data.patches || []
  } catch (e) {
    error.value = e?.response?.data?.error || '补丁查询失败。'
  } finally {
    patchLoading.value = false
  }
}

async function onIngest() {
  ingesting.value = true
  message.value = ''
  error.value = ''
  try {
    const payload = {
      text: ingestForm.text,
      extractor_mode: ingestForm.extractor_mode,
      hints: {
        vendor: ingestForm.vendor || undefined,
        series: ingestForm.series || undefined,
        model: ingestForm.model || undefined,
        upgrade_path: ingestForm.upgrade_path || undefined,
      },
    }
    const { data } = await ingestDocument(payload)
    message.value = `导入成功: 识别 ${data.records} 条，新增 ${data.inserted} 条，更新 ${data.updated} 条，模式 ${data.extractor_mode}。`
  } catch (e) {
    error.value = e?.response?.data?.error || '导入失败。'
  } finally {
    ingesting.value = false
  }
}
</script>

<template>
  <h1>工控设备固件漏洞知识库</h1>

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
    <h2>文档导入（NLP + 大模型）</h2>
    <label>
      文档内容
      <textarea v-model="ingestForm.text" placeholder="粘贴 PDF/网页解析后的文本内容"></textarea>
    </label>
    <div class="grid">
      <label>
        抽取模式
        <select v-model="ingestForm.extractor_mode">
          <option value="hybrid">hybrid（推荐）</option>
          <option value="llm">llm</option>
          <option value="rule">rule</option>
          <option value="auto">auto</option>
        </select>
      </label>
      <label>
        厂商
        <input v-model="ingestForm.vendor" />
      </label>
      <label>
        产品系列
        <input v-model="ingestForm.series" />
      </label>
      <label>
        产品型号
        <input v-model="ingestForm.model" />
      </label>
      <label>
        升级路径
        <input v-model="ingestForm.upgrade_path" />
      </label>
    </div>
    <div class="actions">
      <button :disabled="ingesting" @click="onIngest">{{ ingesting ? '导入中...' : '执行导入' }}</button>
      <span v-if="message" class="badge">{{ message }}</span>
    </div>
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
          <td>{{ item.description }}</td>
          <td>
            <button :disabled="patchLoading" @click="onQueryPatches(item.cve_id)">查补丁</button>
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
        <tr v-for="p in patches" :key="p.patch_id">
          <td>{{ p.patch_id }}</td>
          <td>{{ p.upgrade_path || '-' }}</td>
        </tr>
      </tbody>
    </table>
  </section>

  <p v-if="error" class="error">{{ error }}</p>
</template>
