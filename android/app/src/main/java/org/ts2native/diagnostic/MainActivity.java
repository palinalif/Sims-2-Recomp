package org.ts2native.diagnostic;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.content.SharedPreferences;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.hardware.input.InputManager;
import android.os.Bundle;
import android.util.Log;
import android.view.Choreographer;
import android.view.InputDevice;
import android.view.KeyEvent;
import android.view.MotionEvent;
import android.view.Surface;
import android.view.SurfaceHolder;
import android.view.SurfaceView;
import android.view.View;
import android.view.WindowManager;
import android.view.inputmethod.InputMethodManager;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public final class MainActivity extends Activity implements SurfaceHolder.Callback,
        InputManager.InputDeviceListener, Choreographer.FrameCallback {
    static { System.loadLibrary("ts2_android"); }
    private static native void nativeSurface(Surface surface);
    private static native void nativePad(boolean connected, int buttons, float lx, float ly,
            float rx, float ry, float lt, float rt);
    private static native void nativeReset();
    private static native void nativePointer(float x, float y, boolean select);
    private static native int nativeFrame(float seconds);
    private static native String nativeStatus();
    private static native boolean nativeConfigure(float deadzone, float sensitivity, int[] mapping);
    private static native void nativeToggleMode();
    private static native String nativeLeafDifferential();
    private DiagnosticSurface surface;
    private TextView status;
    private InputManager devices;
    private SharedPreferences prefs;
    private final ExecutorService scanner = Executors.newSingleThreadExecutor();
    private boolean resumed, surfaceReady, dialogOpen, scanBusy;
    private PackageInspector.Result pendingPackage;
    private long lastFrame, lastStatus;
    private int activeDevice=-1, keyButtons, hatButtons;
    private float lx, ly, rx, ry, lt, rt;
    private String deviceLabel="No controller — touch/mouse available";
    private String filesLabel="Choose your own installation using Game files";
    private static final int PICK_TREE=100,PICK_PACKAGE=101;
    private static final String[] TILES={"Game files", "Text entry", "Input mode", "Sensitivity", "Mappings", "Reset input"};
    private static final String[] BUTTONS={"A", "B", "X", "Y", "LB", "RB", "Start", "Select", "L3", "R3", "D-pad up", "D-pad down", "D-pad left", "D-pad right"};
    private static final String[] ACTIONS={"Select", "Cancel", "Context", "Next Sim", "Rotate left", "Rotate right", "Pause / menu", "Toggle mode", "Speed down", "Speed up", "Focus up", "Focus down", "Focus left", "Focus right", "Build / Buy", "Text entry"};
    private final class DiagnosticSurface extends SurfaceView {
        private float pointerX=.5f,pointerY=.5f;
        DiagnosticSurface() { super(MainActivity.this); }
        @Override public boolean performClick() {
            super.performClick();nativePointer(pointerX,pointerY,true);return true;
        }
        @Override public boolean onTouchEvent(MotionEvent event) {
            if(dialogOpen) return false;
            pointerX=event.getX()/Math.max(1,getWidth());pointerY=event.getY()/Math.max(1,getHeight());
            nativePointer(pointerX,pointerY,false);
            if(event.getActionMasked()==MotionEvent.ACTION_UP) performClick();
            return true;
        }
    }

    @Override public void onCreate(Bundle saved) {
        super.onCreate(saved);
        prefs=getSharedPreferences("input",MODE_PRIVATE);
        devices=(InputManager)getSystemService(INPUT_SERVICE);
        FrameLayout root=new FrameLayout(this);
        root.setOnApplyWindowInsetsListener((view,insets)-> {
            // Android 15+ can lay the activity under system bars even with this theme.
            view.setPadding(insets.getSystemWindowInsetLeft(),insets.getSystemWindowInsetTop(),
                    insets.getSystemWindowInsetRight(),insets.getSystemWindowInsetBottom());
            return insets;
        });
        surface=new DiagnosticSurface();surface.getHolder().addCallback(this);
        root.addView(surface,new FrameLayout.LayoutParams(-1,-1));
        View labels=new View(this) {
            final Paint paint=new Paint(Paint.ANTI_ALIAS_FLAG);
            @Override protected void onDraw(Canvas canvas) {
                paint.setColor(Color.WHITE);paint.setTextSize(Math.min(getWidth()/40f,getHeight()/28f));
                for(int i=0;i<TILES.length;i++) canvas.drawText((i+1)+". "+TILES[i],
                        (.1f+.28f*(i%3))*getWidth(),(.42f+.22f*(i/3))*getHeight(),paint);
            }
        };
        labels.setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_NO);
        root.addView(labels,new FrameLayout.LayoutParams(-1,-1));
        status=new TextView(this);status.setTextColor(Color.WHITE);status.setTextSize(13);
        status.setPadding(16,8,16,0);status.setBackgroundColor(0x66101820);
        FrameLayout.LayoutParams textParams=new FrameLayout.LayoutParams(-1,-2);
        root.addView(status,textParams);
        setContentView(root);
        surface.setFocusableInTouchMode(true);surface.requestFocus();
        surface.setContentDescription("Controller diagnostic grid. D-pad changes focus, A activates; Select changes input mode.");
        configure();
        log("native_library_loaded");
        // Explicit owner probe only, off the UI thread. Never a game-start request.
        String probeNonce=getIntent().getStringExtra("ts2_leaf_probe");
        if(probeNonce!=null && probeNonce.matches("[0-9a-f]{32}")) {
            scanner.execute(()->Log.i("TS2Native","{\"event\":\"private_leaf_probe\",\"nonce\":\""
                    +probeNonce+"\",\"result\":"+nativeLeafDifferential()+"}"));
        }
    }
    private void configure() {
        int[] mapping=new int[BUTTONS.length];
        for(int i=0;i<mapping.length;i++) mapping[i]=prefs.getInt("button_"+i,i);
        if(!nativeConfigure(prefs.getFloat("deadzone",.18f),prefs.getFloat("sensitivity",.55f),mapping)) {
            prefs.edit().clear().apply();
            for(int i=0;i<mapping.length;i++) mapping[i]=i;
            nativeConfigure(.18f,.55f,mapping);
        }
    }
    private static void log(String event) { Log.i("TS2Native","{\"component\":\"android\",\"event\":\""+event+"\"}"); }
    @Override protected void onResume() {
        super.onResume();resumed=true;lastFrame=0;
        devices.registerInputDeviceListener(this,null); refreshDevices();
        Choreographer.getInstance().postFrameCallback(this);log("resume");
    }
    @Override protected void onPause() {
        resumed=false;Choreographer.getInstance().removeFrameCallback(this);
        devices.unregisterInputDeviceListener(this);resetInput();log("pause");super.onPause();
    }
    @Override protected void onDestroy() {
        if(pendingPackage!=null && pendingPackage.preview!=null) pendingPackage.preview.recycle();
        pendingPackage=null;
        scanner.shutdownNow();nativeSurface(null);super.onDestroy();
    }
    @Override public void onWindowFocusChanged(boolean focused) {
        super.onWindowFocusChanged(focused);if(!focused) resetInput();lastFrame=0;
    }
    @Override public void surfaceCreated(SurfaceHolder holder) {
        nativeSurface(holder.getSurface());surfaceReady=true;lastFrame=0;
    }
    @Override public void surfaceChanged(SurfaceHolder holder,int format,int w,int h) {
        nativeSurface(holder.getSurface());lastFrame=0;
    }
    @Override public void surfaceDestroyed(SurfaceHolder holder) {
        surfaceReady=false;nativeSurface(null);resetInput();
    }
    @Override public void doFrame(long now) {
        if(!resumed) return;
        if(pendingPackage!=null && surfaceReady && hasWindowFocus() && !dialogOpen) {
            PackageInspector.Result ready=pendingPackage;pendingPackage=null;showPackage(ready);
        }
        if(surfaceReady && hasWindowFocus() && !dialogOpen) {
            int selected=nativeFrame(lastFrame==0?0:Math.min((now-lastFrame)/1e9f,.05f));
            if(selected>=0) activate(selected);
        }
        lastFrame=now;
        if(now-lastStatus>200_000_000L) {
            status.setText(getString(R.string.diagnostic_status,nativeStatus(),deviceLabel,filesLabel));
            lastStatus=now;
        }
        Choreographer.getInstance().postFrameCallback(this);
    }
    private void activate(int index) {
        switch(index) {
            case 0:
                if(scanBusy) { toast("An installation scan is already running"); return; }
                chooseFiles();break;
            case 1: textEntry();break;
            case 2: nativeToggleMode();break;
            case 3:
                dialogOpen=true;
                new AlertDialog.Builder(this).setTitle("Cursor sensitivity")
                    .setItems(new String[]{"Precise", "Standard", "Fast", "Deadzone: 10%", "Deadzone: 18%", "Deadzone: 25%"},(dialog,which)-> {
                        if(which<3) prefs.edit().putFloat("sensitivity",new float[]{.3f,.55f,1.f}[which]).apply();
                        else prefs.edit().putFloat("deadzone",new float[]{.1f,.18f,.25f}[which-3]).apply();
                        configure();
                    }).setOnDismissListener(d->{dialogOpen=false;resetInput();}).show();break;
            case 4: mappings();break;
            default: resetInput();toast("Input released");
        }
    }
    private void chooseFiles() {
        dialogOpen=true;
        new AlertDialog.Builder(this).setTitle("Game files")
            .setItems(new String[]{"Scan installation folder", "Inspect one package (up to 16 MiB)"},(dialog,which)-> {
                Intent intent=new Intent(which==0?Intent.ACTION_OPEN_DOCUMENT_TREE:Intent.ACTION_OPEN_DOCUMENT);
                intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
                if(which==0) intent.addFlags(Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION);
                else { intent.setType("*/*");intent.addCategory(Intent.CATEGORY_OPENABLE); }
                startActivityForResult(intent,which==0?PICK_TREE:PICK_PACKAGE);
            }).setOnDismissListener(d->{dialogOpen=false;resetInput();}).show();
    }
    private void inspectPackage(android.net.Uri uri) {
        scanBusy=true;filesLabel="Reading selected package…";
        scanner.execute(()-> {
            PackageInspector.Result result=null;String error=null;
            try { result=PackageInspector.inspect(this,uri); }
            catch(Exception e) { error="Package inspection failed: "+e.getMessage();log("package_probe_failed"); }
            final PackageInspector.Result inspected=result;final String failed=error;
            runOnUiThread(()-> {
                scanBusy=false;
                if(isDestroyed()) { if(inspected!=null && inspected.preview!=null) inspected.preview.recycle();return; }
                if(failed!=null) { filesLabel=failed;toast(failed);return; }
                filesLabel=inspected.summary.split("\n",2)[0];
                if(pendingPackage!=null && pendingPackage.preview!=null) pendingPackage.preview.recycle();
                pendingPackage=inspected;
            });
        });
    }
    private void showPackage(PackageInspector.Result inspected) {
        dialogOpen=true;
        LinearLayout content=new LinearLayout(this);content.setOrientation(LinearLayout.VERTICAL);
        TextView text=new TextView(this);text.setText(inspected.summary);text.setPadding(24,16,24,16);content.addView(text);
        if(inspected.preview!=null) {
            ImageView image=new ImageView(this);image.setAdjustViewBounds(true);image.setImageBitmap(inspected.preview);
            image.setContentDescription("Selected game package image preview");content.addView(image);
        }
        ScrollView scroll=new ScrollView(this);scroll.addView(content);
        new AlertDialog.Builder(this).setTitle("Package resource").setView(scroll).setPositiveButton("Done",null)
            .setOnDismissListener(d->{dialogOpen=false;resetInput();}).show();
    }
    private void mappings() {
        dialogOpen=true;
        final AlertDialog[] chooser=new AlertDialog[1];
        chooser[0]=new AlertDialog.Builder(this).setTitle("Choose controller button")
            .setItems(BUTTONS,(dialog,button)-> {
                // Post until the first chooser's dismiss callback has run.
                surface.post(()-> {
                    dialogOpen=true;
                    new AlertDialog.Builder(this).setTitle(BUTTONS[button]+" action")
                        .setSingleChoiceItems(ACTIONS,prefs.getInt("button_"+button,button),(selection,action)-> {
                            prefs.edit().putInt("button_"+button,action).apply();configure();selection.dismiss();
                        }).setNegativeButton("Cancel",null)
                        .setOnDismissListener(d->{dialogOpen=false;resetInput();}).show();
                });
            }).setNegativeButton("Reset mappings",(d,w)->{prefs.edit().clear().apply();configure();})
            .setOnDismissListener(d->{dialogOpen=false;resetInput();}).create();
        chooser[0].show();
    }
    private void textEntry() {
        dialogOpen=true;EditText text=new EditText(this);text.setSingleLine(true);
        text.setHint("Diagnostic text — no game connected");
        AlertDialog dialog=new AlertDialog.Builder(this).setTitle("Text entry").setView(text)
            .setPositiveButton("Done",(d,w)->toast("Received "+text.length()+" characters"))
            .setNegativeButton("Cancel",null).setOnDismissListener(d->{dialogOpen=false;resetInput();}).create();
        dialog.setOnShowListener(d->{text.requestFocus();((InputMethodManager)getSystemService(INPUT_METHOD_SERVICE)).showSoftInput(text,InputMethodManager.SHOW_IMPLICIT);});
        dialog.show();
        dialog.getWindow().setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_STATE_ALWAYS_VISIBLE);
    }
    @Override protected void onActivityResult(int request,int result,Intent data) {
        super.onActivityResult(request,result,data);
        if(request==PICK_PACKAGE) {
            if(result==RESULT_OK && data!=null && data.getData()!=null) inspectPackage(data.getData());
            return;
        }
        if(request!=PICK_TREE || result!=RESULT_OK || data==null || data.getData()==null) return;
        android.net.Uri uri=data.getData();
        try {
            if((data.getFlags() & Intent.FLAG_GRANT_READ_URI_PERMISSION)!=0)
                getContentResolver().takePersistableUriPermission(uri,Intent.FLAG_GRANT_READ_URI_PERMISSION);
            prefs.edit().putString("tree",uri.toString()).apply();
        } catch(SecurityException e) { toast("Provider did not retain access; scan is temporary"); }
        scanBusy=true;filesLabel="Scanning selected tree (read only)…";
        scanner.execute(()-> {
            String message;
            try { message=InstallScanner.scan(this,uri); }
            catch(Exception e) { message="Scan failed: "+e.getClass().getSimpleName()+": "+e.getMessage();log("scan_failed"); }
            final String report=message;
            runOnUiThread(()->{scanBusy=false;filesLabel=report;if(!isDestroyed()) toast(report);});
        });
    }
    private void toast(String text) { Toast.makeText(this,text,Toast.LENGTH_LONG).show(); }
    private static boolean isPad(InputDevice device) {
        return device!=null && ((device.getSources() & InputDevice.SOURCE_GAMEPAD)==InputDevice.SOURCE_GAMEPAD
            || (device.getSources() & InputDevice.SOURCE_JOYSTICK)==InputDevice.SOURCE_JOYSTICK);
    }
    private void refreshDevices() {
        int count=0;
        for(int id:InputDevice.getDeviceIds()) if(isPad(InputDevice.getDevice(id))) count++;
        deviceLabel=count==0?"No controller — touch/mouse available":count+" controller(s) — move a stick or press a button";
        if(activeDevice>=0 && InputDevice.getDevice(activeDevice)==null) resetInput();
    }
    private void useDevice(InputDevice device) {
        if(activeDevice!=device.getId()) { resetInput();activeDevice=device.getId(); }
        deviceLabel="Controller: "+device.getName()+" · A/B/X/Y positional prompts";
    }
    private void resetInput() {
        activeDevice=-1;keyButtons=hatButtons=0;lx=ly=rx=ry=lt=rt=0;nativeReset();
    }
    private void sendPad() { nativePad(activeDevice>=0,keyButtons|hatButtons,lx,ly,rx,ry,lt,rt); }
    private static float axis(MotionEvent event,int axis) {
        return event.getDevice().getMotionRange(axis,event.getSource())==null?0:event.getAxisValue(axis);
    }
    @Override public boolean onGenericMotionEvent(MotionEvent event) {
        if(dialogOpen) return super.onGenericMotionEvent(event);
        if((event.getSource() & InputDevice.SOURCE_JOYSTICK)==InputDevice.SOURCE_JOYSTICK && isPad(event.getDevice())) {
            useDevice(event.getDevice());lx=axis(event,MotionEvent.AXIS_X);ly=axis(event,MotionEvent.AXIS_Y);
            boolean standard=event.getDevice().getMotionRange(MotionEvent.AXIS_RZ,event.getSource())!=null;
            rx=axis(event,standard?MotionEvent.AXIS_Z:MotionEvent.AXIS_RX);
            ry=axis(event,standard?MotionEvent.AXIS_RZ:MotionEvent.AXIS_RY);
            lt=Math.max(axis(event,MotionEvent.AXIS_LTRIGGER),axis(event,MotionEvent.AXIS_BRAKE));
            rt=Math.max(axis(event,MotionEvent.AXIS_RTRIGGER),axis(event,MotionEvent.AXIS_GAS));
            hatButtons=0;float hx=axis(event,MotionEvent.AXIS_HAT_X),hy=axis(event,MotionEvent.AXIS_HAT_Y);
            if(hx<-.5f) hatButtons|=1<<12;if(hx>.5f) hatButtons|=1<<13;
            if(hy<-.5f) hatButtons|=1<<10;if(hy>.5f) hatButtons|=1<<11;
            sendPad();return true;
        }
        if((event.getSource() & InputDevice.SOURCE_MOUSE)==InputDevice.SOURCE_MOUSE) {
            nativePointer(event.getX()/Math.max(1,surface.getWidth()),event.getY()/Math.max(1,surface.getHeight()),false);return true;
        }
        return super.onGenericMotionEvent(event);
    }
    private static int button(int key) {
        switch(key) {
            case KeyEvent.KEYCODE_BUTTON_A:case KeyEvent.KEYCODE_DPAD_CENTER:case KeyEvent.KEYCODE_ENTER:return 0;
            case KeyEvent.KEYCODE_BUTTON_B:return 1;
            case KeyEvent.KEYCODE_BUTTON_X:return 2;case KeyEvent.KEYCODE_BUTTON_Y:return 3;
            case KeyEvent.KEYCODE_BUTTON_L1:return 4;case KeyEvent.KEYCODE_BUTTON_R1:return 5;
            case KeyEvent.KEYCODE_BUTTON_START:return 6;case KeyEvent.KEYCODE_BUTTON_SELECT:return 7;
            case KeyEvent.KEYCODE_BUTTON_THUMBL:return 8;case KeyEvent.KEYCODE_BUTTON_THUMBR:return 9;
            case KeyEvent.KEYCODE_DPAD_UP:return 10;case KeyEvent.KEYCODE_DPAD_DOWN:return 11;
            case KeyEvent.KEYCODE_DPAD_LEFT:return 12;case KeyEvent.KEYCODE_DPAD_RIGHT:return 13;
            default:return -1;
        }
    }
    @Override public boolean dispatchKeyEvent(KeyEvent event) {
        if(dialogOpen || !hasWindowFocus()) return super.dispatchKeyEvent(event);
        int b=button(event.getKeyCode());
        if(b<0) return super.dispatchKeyEvent(event);
        if(event.getAction()!=KeyEvent.ACTION_DOWN && event.getAction()!=KeyEvent.ACTION_UP) return true;
        InputDevice device=event.getDevice();
        if(device!=null) useDevice(device); else activeDevice=-2;
        if(event.getAction()==KeyEvent.ACTION_DOWN) keyButtons|=1<<b;else keyButtons&=~(1<<b);
        nativePad(true,keyButtons|hatButtons,lx,ly,rx,ry,lt,rt);return true;
    }
    @Override public void onInputDeviceAdded(int id) { refreshDevices();log("controller_added"); }
    @Override public void onInputDeviceChanged(int id) { if(id==activeDevice) resetInput();refreshDevices();log("controller_changed"); }
    @Override public void onInputDeviceRemoved(int id) { if(id==activeDevice) resetInput();refreshDevices();log("controller_removed"); }
}
