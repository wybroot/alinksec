<template><el-dialog width="min(560px, 94vw)" top="6vh" style="max-height:88vh;overflow-y:auto" :model-value="modelValue" title="修改密码" @update:model-value="$emit('update:modelValue',$event)" @closed="oldPassword='';password='';confirm='';error=''">
  <p v-if="error" role="alert">{{ error }}</p><el-form label-width="110px"><el-form-item label="原密码"><el-input v-model="oldPassword" type="password" autocomplete="current-password"/></el-form-item><el-form-item label="新密码"><el-input v-model="password" type="password" autocomplete="new-password"/></el-form-item><el-form-item label="确认新密码"><el-input v-model="confirm" type="password" autocomplete="new-password"/></el-form-item></el-form><p>至少12字符且不超过72个UTF-8字节。成功后所有现有会话失效，需要重新登录。</p><template #footer><el-button :loading="busy" @click="save">修改密码</el-button></template>
</el-dialog></template>
<script setup>
import {ref} from 'vue'
import {changePassword,clearSession} from '../api'
defineProps({modelValue:Boolean});defineEmits(['update:modelValue'])
const oldPassword=ref(''),password=ref(''),confirm=ref(''),error=ref(''),busy=ref(false)
async function save(){if(busy.value)return;if(password.value!==confirm.value){error.value='两次新密码不一致';return}busy.value=true;try{await changePassword(oldPassword.value,password.value);clearSession();location.href='/login'}catch(e){error.value=e.message}finally{busy.value=false}}
</script>
