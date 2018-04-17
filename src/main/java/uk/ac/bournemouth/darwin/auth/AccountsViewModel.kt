package uk.ac.bournemouth.darwin.auth

import android.accounts.Account
import android.accounts.AccountManager
import android.app.Activity
import android.app.Application
import android.arch.lifecycle.AndroidViewModel
import android.arch.lifecycle.LiveData
import android.arch.lifecycle.MutableLiveData
import android.support.annotation.UiThread
import android.text.format.DateUtils
import android.util.Log
import kotlinx.coroutines.experimental.CoroutineStart
import kotlinx.coroutines.experimental.launch
import nl.adaptivity.android.coroutines.getAuthToken

class AccountsViewModel(application: Application) : AndroidViewModel(application) {
    private val accounts = mutableMapOf<Account, MutableLiveData<AccountInfo>>()

    var reloadMs: Long = DateUtils.MINUTE_IN_MILLIS

    private val _loading= MutableLiveData<Boolean>().apply { setValue(false) }
    val loading: LiveData<Boolean> get() = _loading

    @UiThread
    fun getAccountInfo(activity: Activity, account: Account, forceReload: Boolean = false): LiveData<AccountInfo> {
        return accounts.getOrPut(account) {
            MutableLiveData()
        }.also { liveData ->
            val now = System.currentTimeMillis()
            // We either force a reload because we are forced, or because the data is stale
            if (forceReload || (liveData.value?.lookupTimeMs ?: 0L) + reloadMs < now) {
                val authBaseUrl = getAuthBase(AccountManager.get(getApplication()), account)
                _loading.value = true
                // Use undispatched
                launch(start = CoroutineStart.UNDISPATCHED) {
                    try {
                        val am = AccountManager.get(getApplication())
                        val token = am.getAuthToken(activity, account, DWN_ACCOUNT_TOKEN_TYPE)
                        Log.d("AccountDetailFragment", "authtoken: $token")

                        val info = getAccountInfoHelper(authBaseUrl, token)

                        if (info != null) {
                            liveData.postValue(info)
                        } else {
                            am.invalidateAuthToken(DWN_ACCOUNT_TYPE, token)
                            getAccountInfoHelper(authBaseUrl, token)?.let { liveData.postValue(it) }
                        }
                    } finally {
                        _loading.postValue(false)
                    }

                }
            }
        }
    }
}
