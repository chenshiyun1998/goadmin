const tab = {
  state: {
    current_tab:'second'
  },
  mutations: {
    CURRENT_TAB: (state, data) => {
      state.current_tab = data
    }
  },
  actions: {
    setCurrentTab({ commit }, data) {
      commit('CURRENT_TAB', data)
    }
  }
}

export default tab
