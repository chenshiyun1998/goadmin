<template>
<el-card class="box-card">
  <el-row>
    <el-col :span="10">
      <el-form
        :model="employeeForm"
        label-width="90px"
        :rules="editFormRules"
        ref="employeeForm"
        class="form"
      >
      <el-form-item label="用户帐号" prop="account" >
          <el-input v-model="employeeForm.account" placeholder="请输入用户账号" :disabled="isUpdate"></el-input>
        </el-form-item>
        <el-form-item label="密码" prop="password" v-if="!isUpdate">
          <el-input type="password" v-model="employeeForm.password" placeholder="请输入密码"></el-input>
        </el-form-item>
        <el-form-item label="确认密码" prop="password2" v-if="!isUpdate">
          <el-input type="password" v-model="employeeForm.password2" placeholder="请输入确认密码"></el-input>
        </el-form-item>
        <el-form-item label="用户姓名" prop="name">
          <el-input v-model="employeeForm.name" placeholder="请输入用户姓名"></el-input>
        </el-form-item>
        <el-form-item label="联系方式" prop="phone">
          <el-input v-model="employeeForm.phone" placeholder="请输入联系方式"></el-input>
        </el-form-item>
        <el-form-item label="角色" prop="role_id" v-if="!isBuildin">
          <el-select v-model="employeeForm.role_id" style="width:100%">
            <el-option v-for="item in roles" :key="item.id" :label="item.name" :value="item.id"></el-option>
          </el-select>
        </el-form-item>
        <el-form-item>
          <el-button @click="submit" type="primary">确定</el-button>
        </el-form-item>
      </el-form>
    </el-col>
  </el-row>
</el-card>
</template>
<script>
import { Notification } from "element-ui"
import { LocalAccount } from "@/api/local-account"
import { saveEmployee, getEmployee, findRoles } from "@/api/api"

export default {
  data() {
    var validatePass = (rule, value, callback) => {
      if (value == "") {
        callback(new Error("请输入密码"))
      } else {
        if (this.employeeForm.password2 !== "") {
          this.$refs.employeeForm.validateField("password2")
        }
        callback()
      }
    }
    var validatePass2 = (rule, value, callback) => {
      if (value == "") {
        callback(new Error("请再次输入密码"))
      } else if (value !== this.employeeForm.password) {
        callback(new Error("两次输入密码不一致!"))
      } else {
        callback()
      }
    }
    return {
      isUpdate: false,
      disabled:false,
      roles: [],
      employeeForm: {},
      editFormRules: {
        name: [{ required: true, message: "用户姓名不能为空", trigger: "blur" }],
        phone: [{ required: true, message: "联系方式不能为空", trigger: "blur" }],
        role_id: [
          {
            type: "number",
            required: true,
            message: "用户角色不能为空",
            trigger: "change"
          }
        ],
        account: [{ required: true, message: "帐号不能为空", trigger: "blur" }],
        password: [{ validator: validatePass, trigger: "blur" }],
        password2: [{ validator: validatePass2, trigger: "blur" }]
      },
      loading: false,
      isBuildin:false,
      employee: LocalAccount.getUserInfo(),
    }
  },
  created() {
    this.fetchRoles()
    this.disabled = false
    if (this.$route.query.id) {
      this.isUpdate = true
      getEmployee({ id: this.$route.query.id }).then(result => {
        if (result.code === 0) {
          this.employeeForm = result.data
        }
      })
    }
  },
  methods: {
    submit() {
      let role = _.find(this.roles, {id: this.employeeForm.role_id})
      if (!role) return

      this.employeeForm.role_name = role.name
      this.$refs.employeeForm.validate(valid => {
        if (valid) {
          saveEmployee(this.employeeForm).then(result => {
            if (result.code == 0) {
              Notification.success({
                title: "系统提示",
                message: (this.isUpdate ? "修改" : "新增") + "成功！",
                duration: 2000
              })
              this.$router.push({ path: "/sys/employees" })
            }
          })
        }
      })
    },
    fetchRoles() {
      findRoles().then(result => {
        if(result.code == 0) {
          this.roles = result.data
        }
      })
    },
  }
}
</script>
<style scoped>
.form {
  padding-top: 20px
}
</style>
