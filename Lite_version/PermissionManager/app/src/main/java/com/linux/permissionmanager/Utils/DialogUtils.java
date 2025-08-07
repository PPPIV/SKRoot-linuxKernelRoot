package com.linux.permissionmanager.Utils;

import android.content.Context;
import android.content.DialogInterface;
import android.graphics.drawable.Drawable;
import android.os.Handler;
import android.os.Message;
import android.widget.EditText;

import androidx.appcompat.app.AlertDialog;

public class DialogUtils {

    /**
     * 显示带有消息的对话框。
     *
     * @param context 上下文
     * @param title   对话框标题
     * @param msg     对话框内容
     * @param icon    对话框图标（可为 null）
     */
    public static void showMsgDlg(Context context, String title, String msg, Drawable icon) {
        AlertDialog.Builder builder = new AlertDialog.Builder(context);
        builder.setTitle(title);
        builder.setMessage(msg);
        if (icon != null) {
            builder.setIcon(icon);
        }
        builder.setPositiveButton("确定", new DialogInterface.OnClickListener() {
            public void onClick(DialogInterface dialog, int id) {
                dialog.dismiss();
            }
        });
        AlertDialog dialog = builder.create();
        dialog.show();
    }

    /**
     * 显示带有三个按钮的输入对话框。
     *
     * @param context           上下文
     * @param defaultText       默认文本
     * @param title             对话框标题
     * @param thirdButtonText   第三个按钮的文本
     * @param confirmCallback   点击确定按钮时的回调
     * @param thirdButtonCallback 第三个按钮的回调
     */
    public static void showInputDlg(Context context, String defaultText, String title, final String thirdButtonText,
                                    final Handler confirmCallback, final Handler thirdButtonCallback) {
        final EditText inputTxt = new EditText(context);
        inputTxt.setText(defaultText);
        inputTxt.setFocusable(true);
        inputTxt.setSelection(defaultText.length(), 0);

        AlertDialog.Builder builder = new AlertDialog.Builder(context);
        builder.setTitle(title)
                .setIcon(android.R.drawable.ic_dialog_info)
                .setView(inputTxt)
                .setNegativeButton("取消", new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialog, int which) {
                        dialog.dismiss();
                    }
                })
                .setPositiveButton("确定", new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface dialog, int which) {
                        String text = inputTxt.getText().toString();
                        Message msg = new Message();
                        msg.obj = text;
                        confirmCallback.sendMessage(msg);
                    }
                });

        // 添加第三个按钮
        if (thirdButtonText != null && !thirdButtonText.isEmpty()) {
            builder.setNeutralButton(thirdButtonText, new DialogInterface.OnClickListener() {
                @Override
                public void onClick(DialogInterface dialog, int which) {
                    // 自定义回调
                    if (thirdButtonCallback != null) {
                        thirdButtonCallback.sendMessage(new Message());
                    }
                }
            });
        }

        AlertDialog dialog = builder.create();
        dialog.show();
    }
}
