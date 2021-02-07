<#import "template.ftl" as layout>
<@layout.registrationLayout; section>
    <#if section = "title">
    MFA Push
    <#elseif section = "header">
    MFA Push
    <#elseif section = "form">
        <form id="loginform" class="${properties.kcFormClass!}" action="${url.loginAction}" method="post">
            <div class="${properties.kcFormGroupClass!}">
                Please accept the push token on your mobile device to continue.<br />
                <#if autorefresh = true>
                <script>
                    setTimeout(() => {
                        document.getElementById('loginform').submit();
                    }, 2000);
                </script>
                </#if>
                <div id="kc-form-buttons" class="${properties.kcFormButtonsClass!}">
                    <div class="${properties.kcFormButtonsWrapperClass!}">
                          <input class="${properties.kcButtonClass!} ${properties.kcButtonDefaultClass!} ${properties.kcButtonLargeClass!}" name="restart" id="kc-cancel" type="submit" value="Send another"/><br /><br />
                    </div>
                </div>
            </div>
        </form>
    </#if>
</@layout.registrationLayout>