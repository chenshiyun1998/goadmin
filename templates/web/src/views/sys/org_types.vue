<template>
    <el-card class="box-card">
        <!--工具条-->
        <el-col :span="24" class="toolbar">
            <el-form :inline="true" :model="search" class="demo-form-inline">
                <el-form-item>
                    <el-input v-model="search.name" placeholder="机构类型名称" clearable></el-input>
                </el-form-item>
                <el-form-item>
                    <el-button @click="fetchOrgTypes" icon="el-icon-search" >查询</el-button>
                </el-form-item>
                <el-form-item>
                    <el-button @click="handleAdd" icon="el-icon-plus" type="primary">新增</el-button>
                </el-form-item>
            </el-form>
        </el-col>
            <tree-table 
                    :data="org_types" 
                    :eval-func="func" 
                    :eval-args="[]" 
                    :expand-all="true"
                    border 
                    ref="treeTable"
                    highlight-current-row>
                    <el-table-column label="创建时间" align="center" prop="created_at" :formatter="dateFormatter"></el-table-column>
                    <el-table-column label="操作" align="center">
                    <template slot-scope="scope">
                        <el-button size="medium" @click="handleAddChild(scope.row)" type="text">新增下级机构类型</el-button>
                        <el-button size="medium" @click="handleEdit(scope.row)" type="text">编辑</el-button>
                    </template>
                </el-table-column>
                </tree-table> 
            <!--<el-table
                    border
                    :data="orgs"
                    style="width: 100%">
                <el-table-column type="index" align="center"></el-table-column>
                <el-table-column prop="name" label="机构类型" align="center"></el-table-column>
                <el-table-column prop="created_at" label="创建时间" align="center"
                                 :formatter="dateFormatter"></el-table-column>
                <el-table-column label="操作" align="center">
                    <template slot-scope="scope">
                        <el-button size="medium" @click="handleEdit(scope.row)" type="text">编辑</el-button>
                    </template>
                </el-table-column>
            </el-table>
        </template>
        <el-pagination 
            class="pull-right clearfix"
            @size-change="handleSizeChange" style="margin-top:10px"
            @current-change="handleCurrentChange"
            :current-page.sync="search.page"
            :page-size="search.limit"
            :page-sizes="page.sizes"
            :total="page.total"
            layout="total, sizes, prev, pager, next, jumper">
        </el-pagination>-->
        <el-dialog
                title="机构类型"
                :visible.sync="dialogVisible"
                size="tiny"
                width="30%">
            <el-form :model="orgTypeForm" :rules="rules" ref="orgTypeForm" 
                label-width="120px"
                label-position="left" >
                <el-form-item prop="name" label="机构类型名称">
                    <el-input v-model="orgTypeForm.name" placeholder="请输入机构类型名称"></el-input>
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
    import treeTable from '@/components/TreeTable'
    import treeToArray from '@/components/customEval'
    import {LocalAccount} from '@/api/local-account'
    import {findOrgTypesTree, saveOrgType} from '@/api/api'
    import moment from 'moment'
    import _ from 'lodash'

    export default {
        components: { treeTable },
        data() {
            return {
                func: treeToArray,
                formInline: {},
                org_types: [],
                orgTypeForm: {
                    id: 0,
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
                    name: [{required: true, message: '机构类型名称不能为空', trigger: 'blur'}],
                },
            }
        },
        created() {
            this.fetchOrgTypes()
        },
        methods: {
            fetchOrgTypes() {
                findOrgTypesTree().then(result => {
                    this.org_types = result.data
                    console.log('org_types: ', this.org_types)
                    //this.page.total = result.total
                })
            },
            handleAdd() {
                this.dialogVisible = true
                this.orgTypeForm = {}
            },
            handleAddChild(row) {
                this.dialogVisible = true
                this.orgTypeForm = {parent_id: row.id}
            },
            handleEdit(row) {
                this.orgTypeForm = _.clone(row)
                this.dialogVisible = true
            },
            handleSave: function () {
                this.$refs.orgTypeForm.validate((valid) => {
                    if (valid) {
                        console.log('form:', this.orgTypeForm)
                        let orgType = this.cloneOrgType()
                        console.log('orgType:', orgType)
                        saveOrgType(orgType).then(result => {
                            if (result.code == 0) {
                                this.$message.success((this.orgTypeForm.id ? '编辑' : '新增') + '机构类型成功！')
                                this.fetchOrgTypes()
                                this.dialogVisible = false
                            }
                        })
                    }
                })
            },
            cloneOrgType() {
                let orgType = _.clone(this.orgTypeForm)
                orgType.parent = undefined
                orgType._expanded = undefined
                orgType._level = undefined
                orgType._marginLeft = undefined
                orgType._width = undefined
                orgType.children = undefined
                return orgType
            },
            dateFormatter(row, column) {
                return moment(row.created_at).format('YYYY-MM-DD HH:MM:SS')
            },
            handleSizeChange(val) {
                this.search.limit = val
                this.fetchOrgTypes()
            },
            handleCurrentChange(val) {
                this.fetchOrgTypes()
            }
        }
    }
</script>

<style scoped>
    .toolbar .el-form-item {
        margin-bottom: 10px
    }
</style>
