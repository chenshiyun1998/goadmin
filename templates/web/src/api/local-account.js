import router from '../router'

var accountKey = 'webadmin_account'
var myStorage = window.localStorage

var LocalAccount = {
  save: function (data) {
    myStorage.setItem(accountKey, JSON.stringify(data))
  },
  set: function(key, value) {
    myStorage.setItem(key, value)
  },
  get: function(key) {
    if (key) {
      var val = myStorage.getItem(key)
      return val
    } 

    var data = myStorage.getItem(accountKey)
    if (data && data !== 'undefined') {
      return JSON.parse(data)
    } else {
      return undefined
    }
  },
  getUserInfo: function () {
    var account = this.get()
    if (account && account.user) {
      return account.user
    } else {
      return undefined
    }
  },
  getRouteLinks: function () {
    var account = this.get()
    if (account && account.user) {
      return account.route_links
    } else {
      return undefined
    }
  },
  getRoleId: function () {
    this.valid()
    let userinfo = this.getUserInfo()
    return userinfo.role_id
  },
  getEmployeeId: function () {
    this.valid()
    let userinfo = this.getUserInfo()
    return userinfo.id
  },
  getToken: function () {
    this.valid()
    var account = this.get()
    if (account && account.jwt) {
      return account.jwt.token
    } else {
      return undefined
    }
  },
  valid: function () {
    let userinfo = LocalAccount.getUserInfo()
    if (!userinfo) {
      router.push({path:'/login'})
    }
  },
  isAuth: function () {
    return !!this.get()
  },
  clear: function () {
    myStorage.clear()
  }
}

export {LocalAccount}
