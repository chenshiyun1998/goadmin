<template>
    <el-card class="box-card">
        <!--工具条-->
        <el-col :span="24" class="toolbar">
            <el-form :inline="true" :model="search" class="demo-form-inline">
                <el-form-item>
                    <el-input v-model="search.name" placeholder="角色名称" clearable></el-input>
                </el-form-item>
                <el-form-item>
                    <el-button @click="fetchRoles" icon="el-icon-search" >查询</el-button>
                </el-form-item>
                <el-form-item>
                    <el-button @click="handleAdd" icon="el-icon-plus" type="primary">新增</el-button>
                </el-form-item>
            </el-form>
        </el-col>
        <!--列表-->
        <template>
            <el-table
                    border
                    :data="roles"
                    style="width: 100%">
                <el-table-column type="index" align="center"></el-table-column>
                <el-table-column prop="name" label="角色名称" align="center"></el-table-column>
                <el-table-column prop="org_type_name" label="机构类型" align="center"></el-table-column>
                <el-table-column prop="created_at" label="创建时间" align="center"
                                 :formatter="dateFormatter"></el-table-column>
                <el-table-column label="操作" align="center">
                    <template slot-scope="scope">
                        <el-button :disabled="disabledEdit(scope.row)" size="medium" @click="handleEdit(scope.row)" type="text">编辑</el-button>
                        <el-button :disabled="disabledEdit(scope.row)" size="medium" @click="handleEditPerms(scope.row)" type="text">权限分配</el-button>
                        <el-button :disabled="disabledEdit(scope.row)" size="medium" @click="handleDelete(scope.row)" type="text">删除</el-button>
                    </template>
                </el-table-column>
            </el-table>
        </template>
        <!--分页-->
        <el-pagination 
            class="pull-right clearfix"
            @size-change="handleSizeChange" style="margin-top:10px"
            @current-change="handleCurrentChange"
            :current-page.sync="search.page"
            :page-size="search.limit"
            :page-sizes="page.sizes"
            :total="page.total"
            layout="total, sizes, prev, pager, next, jumper">
        </el-pagination>
        <el-dialog
                title="角色"
                :visible.sync="dialogVisible"
                size="tiny"
                width="30%">
            <el-form :model="roleForm" :rules="rules" ref="roleForm" 
                label-width="80px"
                label-position="left" >
                <el-form-item prop="name" label="角色名称">
                    <el-input v-model="roleForm.name" placeholder="请输入角色名称"></el-input>
                </el-form-item>
                <el-form-item label="机构类型" v-if="getRoleId() === 1">
                    <el-select v-model="roleForm.org_type_id" placeholder="请选择机构类型" style="width:100%;">
                        <el-option v-for="item in org_types" :key="item.id" :label="item.name" :value="item.id"></el-option>
                    </el-select>
                </el-form-item>
            </el-form>
            <span slot="footer" class="dialog-footer">
        <el-button @click="dialogVisible = false">取 消</el-button>
        <el-button type="primary" @click="handleSave">确 定</el-button>
      </span>
        </el-dialog>
    </el-card>
</template>

<script>
    import {LocalAccount} from '@/api/local-account'
    import {findRoles, saveRole, delRole, findOrgTypesSelect} from '@/api/api'
    import moment from 'moment'
    import _ from 'lodash'

    export default {
        data() {
            return {
                formInline: {},
                roles: [],
                org_types: [],
                roleForm: {
                    id: 0,
                    org_type_id: 0,
                    org_type_name: '',
                    name: ''
                },
                dialogVisible: false,
                search: {
                    page: 1,
                    limit: 10,
                },
                page: {
                    sizes: [10, 20, 30, 50],
                    total: 0
                },
                rules: {
                    name: [{required: true, message: '角色名称不能为空', trigger: 'blur'}],
                    type: [{required: true, message: '角色类型不能为空', trigger: 'blur'}],
                },
            }
        },
        created() {
            this.fetchRoles()
            this.fetchOrgTypes()
        },
        methods: {
            getRoleId() {
                return LocalAccount.getRoleId()
            },
            fetchOrgTypes() {
                findOrgTypesSelect().then(result => {
                    this.org_types = result.data
                })
            },
            fetchRoles() {
                findRoles(this.search).then(result => {
                    this.roles = result.data
                    this.page.total = result.total
                })
            },
            handleAdd() {
                this.dialogVisible = true
                this.roleForm = {}
            },
            handleEdit(row) {
                this.roleForm = _.clone(row)
                this.dialogVisible = true
            },
            disabledEdit(role) {
                return role.buildin === 1
            },
            handleEditPerms(row) {
                this.$router.push({path: '/sys/role_menu', query: {id: row.id, name: row.name}})
            },
            handleSave: function () {
                this.$refs.roleForm.validate((valid) => {
                    if (valid) {
                        let org_type = _.find(this.org_types, {id: this.roleForm.org_type_id})
                        if (LocalAccount.getRoleId() === 1 && !org_type) return
                        if (org_type) {
                            this.roleForm.org_type_name = org_type.name
                        }

                        console.log('this.roleForm: ', this.roleForm)
                        
                        saveRole(this.roleForm).then(result => {
                            if (result.code == 0) {
                                this.$message.success((this.roleForm.id ? '编辑' : '新增') + '角色成功！')
                                this.fetchRoles()
                                this.dialogVisible = false
                            } else {

                            }
                        })
                    }
                })
            },
            dateFormatter(row, column) {
                return moment(row.created_at).format('YYYY-MM-DD HH:MM')
            },
            handleSizeChange(val) {
                this.search.limit = val
                this.fetchRoles()
            },
            handleCurrentChange(val) {
                this.fetchRoles()
            },
            handleDelete(row){
                this.$confirm("您确定要删除"+row.name+"吗?", "提示", {
                    confirmButtonText: "确定",
                    cancelButtonText: "取消",
                    type: "warning"
                }).then(() => {
                    delRole({id:row.id}).then(res=>{
                        if(res.code == 0){
                            this.$message.success('已删除')
                            this.fetchRoles()
                        }
                    })
                })
                .catch(() => {
                    //取消
                    console.log("n")
                })
            }
        }
    }
</script>

<style scoped>
    .toolbar .el-form-item {
        margin-bottom: 10px
    }
</style>
