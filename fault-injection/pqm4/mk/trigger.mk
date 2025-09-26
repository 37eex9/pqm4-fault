# Set compiler flags according to makefile arguments 
# to include trigger calls at desired positions in binary
TRIGGER_DECODE :=$(if $(T_SYND_W),T_SYND_W,$(if $(T_THRESHOLD),T_THRESHOLD,$(if $(T_DECODER_LOOP),T_DECODER_LOOP)))

RETAINED_VARS += TRIGGER_DECODE

CPPFLAGS += \
	-DTRIGGER \
	-DTRIGGER_ADV \
	$(if $(TRIGGER_DECODE), -D$(TRIGGER_DECODE))
