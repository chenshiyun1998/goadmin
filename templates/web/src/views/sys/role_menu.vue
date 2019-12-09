<template>
<el-card class="box-card">
  <section style="background-color:#EAEAEA;">
    <el-row style="padding:5px;">
      <label style="color:red;font-size:18px;">{{role_name}}</label>&nbsp;权限编辑
    </el-row>
    <el-row>
      <el-col :span="24" class="toolbar">
        <el-button @click="handleCheckedAll">全选</el-button>
        <el-button type="danger" @click="handleResetChecked">全不选</el-button>
        <el-button type="success" @click="handleSave">保存</el-button>
        <br>
        <br>
        <el-tree
          :data="menus"
          :props="defaultProps"
          ref="tree"
          show-checkbox
          node-key="id"
          @check-change="handleCheckChange"
          highlight-current
          :expand-on-click-node="true"
          :default-expand-all="true"
          accordion>
        </el-tree>
        <br>
        <el-button @click="handleCheckedAll">全选</el-button>
        <el-button type="danger" @click="handleResetChecked">全不选</el-button>
        <el-button type="success" @click="handleSave">保存</el-button>
      </el-col>
    </el-row>
  </section>
</el-card>
</template>

<script>
  import { Notification } from 'element-ui'
  import {LocalAccount} from '@/api/local-account'
  import {deepDiffMapper} from '@/utils/deep_diff'
  import {findRoleMenus, saveRoleMenus} from '@/api/api'
  export default {
    data() {
      return {
        menu: {
          id: '',
          name: '',
          parent_id: 0,
          type: '',
          api_url: '',
          route_link: '',
          perms: ''
        },
        menus: [],
        original_menus: [],
        level2_menus: [],
        checked_menus: [],
        checked_keys: [],
        defaultProps: {
          children: 'children',
          label: 'name'
        }
      }
    },
    created() {
      this.role_id = this.$route.query.id
      this.role_name = this.$route.query.name
      this.fetchRoleMenus()
    },
    methods: {
      fetchRoleMenus() {
        findRoleMenus({role_id: this.role_id}).then(result=>{
          this.original_menus = _.cloneDeep(result.data)
          this.menus = result.data
          this.setCheckedKeys()
        })
      },
      /*handleSave() {
        let diff = deepDiffMapper.map(this.menu, this.original_menus)
        console.log('diff: ', diff)
        return
        saveSysMenu(this.menu).then(result=>{
          if(result.code === 0) {
            Notification.success({title: '系统提示', message: '修改菜单成功!', duration: 2000})
            this.$refs.menuForm.resetFields()
            this.fetchMenus()
          }
        })
      },*/
      setCheckedKeys() {
        this.menus.forEach(level1Menu=>{
          level1Menu.children.forEach(level2Menu=>{
            if (!level2Menu.children || !level2Menu.children.length) {
              if (level2Menu.checked === 1) {
                this.checked_keys.push(level2Menu.id)
              }
            }
            this.level2_menus.push(level2Menu)
            level2Menu.children.forEach(level3Menu=>{
              if (level3Menu.checked === 1) {
                this.checked_keys.push(level3Menu.id)
              }
            })
          })
        })
        this.$refs.tree.setCheckedKeys(this.checked_keys)
      },
      handleCheckedAll() {
        this.checked_keys = []
        this.level2_menus.forEach(item=>{
          this.checked_keys.push(item.id)
        })
        this.$refs.tree.setCheckedKeys(this.checked_keys)
      },
      handleResetChecked() {
        this.$refs.tree.setCheckedKeys([])
      },
      handleCheckChange(data, checked, indeterminate) {
        if (data.level === 'level2' || data.level === 'level3') {
          data.checked = checked ? 1 : 0
        }
      },
      handleSave() {
        this.checked_menus = []
        this.menus.forEach(level1Menu=>{
          level1Menu.children.forEach(level2Menu=>{
            if (!level2Menu.children || !level2Menu.children.length) {
              if (level2Menu.checked === 1) {
                this.checked_menus.push(level2Menu.id)
              }
            }
            level2Menu.children.forEach(level3Menu=>{
              if (level3Menu.checked === 1) {
                this.checked_menus.push(level3Menu.id)
              }
            })
          })
        })

        let data = {role_id: this.role_id, menu_ids: this.checked_menus}
        saveRoleMenus(data).then(result=>{
          if (result.code == 0) {
            Notification.success({title: '系统提示', message: '权限分配成功！', duration: 2000})
          }
        })
      }
    }
  }
</script>
<style scoped>

</style>
