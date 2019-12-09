<template>
  <el-card class="box-card">
    <!--工具条-->
    <el-form :inline="true" :model="search" class="demo-form-inline">
      <el-form-item>
        <el-input v-model="search.keyword" placeholder="用户账号/用户姓名/联系方式" clearable></el-input>
      </el-form-item>
      <el-form-item>
        <el-button @click="fetchEmployees" icon="el-icon-search">查询</el-button>
      </el-form-item>
      <el-form-item>
        <el-button @click="handleAdd" icon="el-icon-plus" type="primary">新增</el-button>
      </el-form-item>
    </el-form>
    <!--列表-->
    <el-table :data="employees" border>
      <el-table-column type="index" align="center"></el-table-column>
      <el-table-column prop="account" label="用户账号" align="center"></el-table-column>
      <el-table-column prop="name" label="用户姓名" align="center"></el-table-column>
      <el-table-column prop="role_name" label="角色" align="center"></el-table-column>
      <el-table-column prop="phone" label="联系方式" align="center"></el-table-column>
      <el-table-column label="操作" align="center">
        <template slot-scope="scope">
          <el-button type="text" :disabled="scope.row.role_id === 1" @click="handleEdit(scope.$index, scope.row)">编辑</el-button>
          <el-button type="text" @click="handlerResetPW(scope.row)" v-if="scope.row.role_id>6">重置密码</el-button>
          <el-button type="text" @click="handleDel(scope.row)" v-if="scope.row.role_id>6">删除</el-button> 
        </template>
      </el-table-column>
    </el-table>
    <!--分页-->
    <el-pagination
      style="margin-top:10px"
      @size-change="handleSizeChange"
      @current-change="handleCurrentChange"
      :current-page.sync="search.page"
      :page-size="search.limit"
      :page-sizes="page.sizes"
      :total="page.total"
      layout="total, sizes, prev, pager, next, jumper"
    ></el-pagination>
  </el-card>
</template>

<script>
import { Notification } from "element-ui"
import { LocalAccount } from "@/api/local-account"
import {
  findEmployees,
  createEmployee,
  saveEmployee,
  delEmployees,
  resetPasswordEmployee
} from "@/api/api"

export default {
  data() {
    return {
      formInline: {},
      employees: [],
      list:[],
      search: {
        page: 1,
        limit: 10,
      },
      page: {
        sizes: [10, 20, 30, 50],
        total: 0
      },
      qrCode: "",
      show_dialog: false,
    }
  },
  created() {
    this.fetchEmployees()
  },
  methods: {
    handleSizeChange(val) {
      this.search.limit = val
      this.fetchEmployees()
    },
    handleCurrentChange(val) {
      this.fetchEmployees()
    },
    handlerResetPW(item) {
      this.$confirm(
        "确定重置账号" + item.account + "的密码为111111吗？",
        "重置密码",
        {
          confirmButtonText: "确定",
          cancelButtonText: "取消",
          type: "warning"
        }
      )
        .then(() => {
          item.password = "111111"
          resetPasswordEmployee(item).then(result => {
            Notification.success({
              title: "系统提示",
              message: "重置密码成功!",
              duration: 2000
            })
          })
        })
    },
    handleEdit(index, item) {
      this.$router.push({
        path: "/sys/employee_edit",
        query: {
          id: item.id
        }
      })
    },
    fetchEmployees() {
      this.list.length = 0
      console.log(this.search.keyword, '22')
      findEmployees(this.search).then(result => {
        var str1 = JSON.parse(localStorage.getItem("webadmin_account"))
        var my_role_id = str1.user.role_id

        //筛选出role_id大于等于自己的记录，即平级和下级的记录
        this.employees = result.data
        for (var i = 0; i < result.data.length; i++){
          if(my_role_id <= this.employees[i].role_id){
            this.list.push(this.employees[i])
          }
        }
        this.employees = this.list
        this.page.total = result.total
        
      })
    },
    handleAdd: function () {
      this.$router.push({
        path: "/sys/employee_edit"
      })
    },
    handleDel(item) {
      this.$confirm("您确定要删除"+item.name+"吗?", "提示", {
        confirmButtonText: "确定",
        cancelButtonText: "取消",
        type: "warning"
      })
        .then(() => {
          delEmployees([item.id]).then(result => {
            if (result.code == 0) {
              this.fetchEmployees()
              this.$message({
                type: "success",
                message: "删除成功!"
              })
            } else {
              this.$message({
                type: "error",
                message: "删除失败!"
              })
            }
          })
        })
        .catch(() => {
          //取消
        })
    },
    handleQrCode(row) {

    },
  }
}
</script>
<style scoped>
.toolbar {
  margin-top: 10px
}

.pagination {
  padding: 10px;
  float: right
}
</style>
