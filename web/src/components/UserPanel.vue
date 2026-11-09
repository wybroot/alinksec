<template>
  <p v-if="error" role="alert">{{ error }} <el-button @click="load">重试</el-button></p>
  <el-button type="primary" @click="edit()">创建用户</el-button>
  <el-table :data="rows"><el-table-column prop="username" label="用户名"/><el-table-column prop="role" label="角色"/><el-table-column label="状态"><template #default="{row}">{{ Number(row.status)===1?'启用':'停用' }}</template></el-table-column><el-table-column label="操作"><template #default="{row}"><el-button @click="edit(row)">编辑／重置密码</el-button></template></el-table-column></el-table>
  <el-pagination v-model:current-page="page" :page-size="100" :total="total" layout="prev, pager, next" @current-change="load"/>
  <el-dialog width="min(560px, 94vw)" top="6vh" style="max-height:88vh;overflow-y:auto" v-model="visible" title="用户管理" @closed="form.password=''">
    <p v-if="error" role="alert">{{ error }}</p>
    <el-form label-width="100px"><el-form-item label="用户名"><el-input v-model="form.username" :disabled="!!form.id" maxlength="64"/></el-form-item><el-form-item label="姓名" v-if="!form.id"><el-input v-model="form.realName" maxlength="64"/></el-form-item><el-form-item label="角色"><el-select v-model="form.role"><el-option v-for="role in ['admin','operator','viewer']" :key="role" :value="role" :label="role"/></el-select></el-form-item><el-form-item label="状态" v-if="form.id"><el-switch v-model="form.enabled"/></el-form-item><el-form-item label="密码"><el-input v-model="form.password" type="password" show-password autocomplete="new-password"/></el-form-item><p>密码至少 12 字符，最多 72 个 UTF-8 字节。编辑时留空保留密码；角色、状态或密码变更会撤销该账号的现有会话。</p></el-form>
    <template #footer><el-button :loading="busy" @click="save">保存</el-button></template>
  </el-dialog>
</template>
<script setup>
import {ref,onMounted} from 'vue'
import {fetchUsers,createUser,updateUser} from '../api'
const rows=ref([]),page=ref(1),total=ref(0),error=ref(''),visible=ref(false),busy=ref(false),form=ref({})
async function load(){try{const data=await fetchUsers(page.value);rows.value=data.list;total.value=Number(data.total);error.value=''}catch(e){error.value=e.message;rows.value=[]}}
function edit(row){error.value='';form.value={id:row?.id,version:row?.auth_version,username:row?.username || '',realName:'',role:row?.role || 'viewer',enabled:Number(row?.status ?? 1)===1,password:''};visible.value=true}
async function save(){if(busy.value)return;busy.value=true;try{const f=form.value,body={username:f.username,realName:f.realName,role:f.role,status:String(f.enabled?1:0)};if(f.password)body.password=f.password;if(f.id){body.version=String(f.version);await updateUser(f.id,body);}else await createUser(body);visible.value=false;await load()}catch(e){error.value=e.message}finally{busy.value=false}}
onMounted(load)
</script>
