<template>
  <el-card class="box-card">
    <el-row>
      <el-form
        :model="employeeForm"
        label-width="90px"
        :rules="editFormRules"
        ref="employeeForm"
        class="form"
      >
        <el-form-item label="原密码" prop="old_password">
          <el-input type="old_password" v-model="employeeForm.old_password" placeholder="请输入原密码"></el-input>
        </el-form-item>
        <el-form-item label="新密码" prop="password">
          <el-input type="password" v-model="employeeForm.password" placeholder="请输入新密码"></el-input>
        </el-form-item>
        <el-form-item label="确认密码" prop="password2">
          <el-input type="password" v-model="employeeForm.password2" placeholder="请输入确认密码"></el-input>
        </el-form-item>

        <el-form-item>
          <el-button @click="submit" type="primary">确定</el-button>
        </el-form-item>
      </el-form>
    </el-row>
  </el-card>
</template>
<script>
import { Notification } from "element-ui"
import { LocalAccount } from "@/api/local-account"
import { updatePasswordEmployee } from "@/api/api"

export default {
  data() {
    var validatePass = (rule, value, callback) => {
      if (value == "") {
        callback(new Error("新密码不能为空"))
      } else {
        if (this.employeeForm.password2 !== "") {
          this.$refs.employeeForm.validateField("password2")
        }
        callback()
      }
    }
    var validatePass2 = (rule, value, callback) => {
      if (value == "") {
        callback(new Error("确认密码不能为空"))
      } else if (value !== this.employeeForm.password) {
        callback(new Error("两次输入密码不一致!"))
      } else {
        callback()
      }
    }
    return {
      employeeForm: {},
      editFormRules: {
        old_password: [
          { required: true, message: "原密码不能为空", trigger: "blur" },
          { min: 6, message: '密码长度不能低于6位', trigger: 'blur' }
        ],
        password: [
          { validator: validatePass, trigger: "blur" },
          { min: 6, message: '密码长度不能低于6位', trigger: 'blur' }
        ],
        password2: [{ validator: validatePass2, trigger: "blur" }]
      },
    }
  },
  created() {
  },
  methods: {
    submit() {
      this.$refs.employeeForm.validate(valid => {
        if (valid) {
          updatePasswordEmployee(this.employeeForm).then(result => {
            if (result.code == 0) {
              this.$message.success('密码已修改,请重新登录！')
              setTimeout(() => {
                this.$store.dispatch('LogOut').then(() => {
                  this.$store.dispatch('setIsLoadedRoutes', false)
                  location.reload()
                })
              }, 2000)
            }
          })
        }
      })
    },
  }
}
</script>
<style scoped>
.form {
  width: 40%;
}
</style>
