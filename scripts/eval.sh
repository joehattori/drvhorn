#!/bin/bash

for driver in \
    platform_driver \
    acpi_wmi_driver \
    ns2_led_driver \
    gti_wdt_driver \
    stm32_iwdg_driver \
    hisi_thermal_driver \
    ptp_qoriq_driver \
    ptp_dte_driver \
    xvtc_driver \
    xtpg_driver \
    xvip_composite_driver \
    brcmstb_i2c_driver \
    i8042_driver \
    bcm_sf2_driver \
    unimac_mdio_driver \
    apple_nvme_driver \
    edma_driver \
    acpi_fan_driver \
    ged_driver \
    alarmtimer_driver; do
  echo Running DrvHorn on $driver..
  docker run --rm joehattori/drvhorn timeout 500 /drvhorn/build/run/bin/sea kernel --platform-driver=$driver /drvhorn/simple_kernel.bc 2>/dev/null
done

